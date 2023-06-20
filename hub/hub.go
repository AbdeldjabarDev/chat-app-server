package hub

import (
	// "encoding/json"
	// "bytes"
	"bytes"
	"chat-server/client"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	// "io/ioutil"

	// "io/ioutil"
	"net/http"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"firebase.google.com/go/storage"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"

	//   "firebase.google.com/go/auth"
	"context"
	"math/big"
	mathrand "math/rand"

	"github.com/google/uuid"
	"google.golang.org/api/iterator"
)

const (
	Text              = byte(0)
	Image             = byte(1)
	Voice             = byte(2)
	MessageReceived   = byte(9)
	MessageDeleivered = byte(3)
	MessageRead       = byte(4)
	EncKeyRequest     = byte(5)
	AuthKeyRequest    = byte(6)
	EncKeyResponse    = byte(7)
	AuthKeyResponse   = byte(8)
	UserTyping        = byte(10)
	UserConnected     = byte(11)
)
const (
	CHAT_APP_OK        = 0
	EMAIL_USED         = 5
	INTERNAL_ERROR     = 500
	INCORRECT_PASSWORD = 2
	INVALID_EMAIL      = 3
	INVALID_CODE       = 4
	NO_ACCOUNT         = 6
)

type Hub struct {
	Clients       map[string]*client.Client
	NumClients    int
	Mqueue        chan *Message
	Tmpids        map[string]string
	FireClient    firestore.Client
	StorageClient storage.Client
	Message_buf   []message
	Accounts      []FullUser
	Mp            *big.Int
	TokenManager  TokenManager
}

type Message struct {
	id            uint32
	timestamp     uint64
	msgType       byte
	payloadLength uint16
	reserved      byte
	authKey       []byte
	senderId      []byte
	receiverId    []byte
	payload       []byte
}
type message struct {
	Id         uint32
	SenderId   []byte
	ReceiverId []byte
	Timestamp  uint64
	State      byte
	MsgType    byte
	Payload    []byte
}
type FullUser struct {
	Email         string `json:"Email"`
	Password      string `json:"Password"`
	Profile_photo string `json:"Profile_photo`
	Public        string `json:"Public"`
	User_name     string `json:"User_name"`
	Acc_id        string `json:"Acc_id"`
}

func randString(n int) string {
	mathrand.Seed(time.Now().UnixNano())

	allowedChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var result string

	for i := 0; i < n; i++ {
		result += string(allowedChars[mathrand.Intn(len(allowedChars))])
	}

	return result
}

func uint642bin(a uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, a)
	return b
}
func uint162bin(a uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, a)
	return b
}
func uint322bin(a uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, a)
	return b
}
func structureMessage(msg client.Message) []byte {
	fmt.Printf("sm : Payload length : %d\n", msg.PayloadLength)
	data := make([]byte, len(msg.Payload)+130)
	fmt.Printf("sm : data before length : %d\n", len(data))
	// i := rand.Intn(8)
	l := uint16(len(msg.Payload))
	// copy(data[0:2], uint162bin(uint16(i)))
	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	copy(data[0:2], uint162bin(l))
	copy(data[2:18], iv)
	data[18] = byte(1)
	copy(data[19:23], uint322bin(msg.Id))
	copy(data[23:55], msg.AuthKey)
	copy(data[55:87], msg.SenderId)
	copy(data[87:119], msg.ReceiverId)
	copy(data[119:127], uint642bin(msg.Timestamp))
	data[127] = msg.MsgType
	copy(data[128:130], uint162bin(msg.PayloadLength))
	// data[129] = byte(0)
	copy(data[130:], msg.Payload)
	if len(data[18:])%16 == 0 {
		fmt.Printf("Input full blocks %d", len(data[18:]))
		return data
	} else {
		fmt.Printf("Input not full blocks %d", len(data[18:]))
		data = append(data, bytes.Repeat([]byte{0x00}, 16-len(data[18:])%16)...)
		fmt.Printf("Input full blocks %d", len(data))
		return data
	}

}
func (h *Hub) unregisterClient(cid string) {
	h.Clients[cid] = nil
	h.NumClients--
}
func (h *Hub) registerClient(cid string, c *client.Client) {
	h.Clients[cid] = c
	h.NumClients++
}
func (h *Hub) CheckClient(cid string) bool {
	return true // for now
}

type TokenManager struct {
	SigningKey    []byte
	ExpiryMinutes int
	CollectionRef *firestore.CollectionRef
}

func NewTokenManager(signingKey []byte, expiryMinutes int, collectionRef *firestore.CollectionRef) (*TokenManager, error) {

	// Create TokenManager instance
	tm := &TokenManager{
		SigningKey:    signingKey,
		ExpiryMinutes: expiryMinutes,
		CollectionRef: collectionRef,
	}

	return tm, nil
}

func (tm *TokenManager) GenerateToken(userID string) (string, error) {
	// Generate a random UUID as the token ID
	tokenID := uuid.New().String()

	// Calculate the expiry time
	expiryTime := time.Now().Add(time.Duration(tm.ExpiryMinutes) * time.Minute).Unix()

	// Construct the token payload
	rn := mathrand.Intn(10000)
	payload := map[string]interface{}{
		"user_id":   userID,
		"token_id":  tokenID,
		"expiry_ts": expiryTime,
		"nonce":     rn}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   userID,
		"token_id":  tokenID,
		"expiry_ts": expiryTime,
		"nonce":     rn})
	// Sign the token payload

	tokenString, err := token.SignedString(tm.SigningKey)
	if err != nil {
		return "", err
	}
	if err != nil {
		return "", err
	}

	// Store the token in the Firestore collection
	docRef := tm.CollectionRef.Doc(tokenID)
	_, err = docRef.Set(context.Background(), payload)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
func (tm *TokenManager) VerifyToken(tokenString string) (bool, error) {
	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid token signing method")
		}
		return tm.SigningKey, nil
	})
	if err != nil {
		return false, err
	}

	// Check if token is valid
	if !token.Valid {
		return false, errors.New("invalid token")
	}
	return true, nil

	// Get token data from Firestore
	// doc, err := tm.CollectionRef.Doc(tokenString).Get(context.Background())
	// if err != nil {
	// 	return "", err
	// }

	// // Check if token has expired
	// data := doc.Data()
	// expiresAt, ok := data["expiresAt"].(time.Time)
	// if !ok {
	// 	return "", errors.New("invalid token data")
	// }
	// if time.Now().After(expiresAt) {
	// 	return "", errors.New("token has expired")
	// }

	// // Return user ID
	// userID, ok := data["userID"].(string)
	// if !ok {
	// 	return "", errors.New("invalid token data")
	// }
	// return userID, nil
}
func getFirstDocByQuery(col *firestore.CollectionRef, prop string, value interface{}) *firestore.DocumentSnapshot {
	docsnapshot, err := col.Where(prop, "==", value).Documents(context.Background()).GetAll()
	if err != nil {
		fmt.Println("Error getting document by query : " + err.Error())
		return nil
	}
	return docsnapshot[0]

}

func (h *Hub) HandleSyncRequest(w http.ResponseWriter, r *http.Request) {
	uid := r.Header.Get("UserId")
	var response []message
	if uid == "" {
		// handle bad request
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	docref := getFirstDocByQuery(h.FireClient.Collection("users"), "Acc_id", uid) // function needs testing
	if docref == nil {
		// handle user not found in db
		http.Error(w, "Unknown user", http.StatusNotFound)
		return
	}
	doc := docref.Data()
	friends := doc["Friends"]
	_arr := friends.([]interface{})
	var arr []string

	for i, e := range _arr {
		arr = append(arr, e.(string))
		fmt.Printf("Friend %d : "+e.(string)+"\n", i)
	}

	for _, s := range arr {
		sarr := []string{uid, s}
		sort.Strings(sarr)
		hasher := sha256.New()
		hasher.Write([]byte(sarr[0] + sarr[1]))
		conv_hash := hex.EncodeToString(hasher.Sum(nil))
		fmt.Printf("SyncRequest : Conversation hash : " + conv_hash)
		messages, err := h.FireClient.Collection(conv_hash).Documents(r.Context()).GetAll()
		if err != nil {
			fmt.Println("failed to get messages for : " + uid + "and : " + s + err.Error())
			// handle error with http error code
			http.Error(w, "Internal server error : failed to acquire messages ", http.StatusInternalServerError)
			return
		}
		fmt.Printf("SyncRequest : got %d messages.\n", len(messages))
		var msgs []message
		for _, m := range messages {
			var mm message
			m.DataTo(&mm)
			msgs = append(msgs, mm)
		}
		response = append(response, msgs...)
	}
	fmt.Printf("SyncRequest : responding with %d messages.\n", len(response))
	json.NewEncoder(w).Encode(response)

}
func (h *Hub) StoreMessage(msg message) {
	sid := hex.EncodeToString(msg.SenderId)
	rid := hex.EncodeToString(msg.ReceiverId)
	arr := []string{sid, rid}
	hasher := sha256.New()
	sort.Strings(arr)
	hasher.Write([]byte(arr[0] + arr[1]))
	hash := hex.EncodeToString(hasher.Sum(nil))
	if msg.MsgType != MessageDeleivered && msg.MsgType != MessageRead && msg.MsgType != MessageReceived {
		_, _, err := h.FireClient.Collection(hash).Add(context.Background(), map[string]interface{}{
			"Id":         msg.Id,
			"RecieverId": msg.ReceiverId,
			"SenderId":   msg.SenderId,
			"MsgType":    msg.MsgType,
			"Payload":    msg.Payload,
			"Timestamp":  int64(msg.Timestamp),
			"State":      msg.State,
		})
		if err != nil {
			fmt.Println("Failed to add message to db : " + err.Error())
		}
	}
	// colNames := make(map[string][]message)
	// if len(h.Message_buf) >= 10 {
	//	hasher := sha256.New();
	// 	fmt.Println("Storing message batch ...")
	// 	for i := 0; i < len(h.Message_buf); i++ {
	//     hasher.Reset();
	//
	// 		arr := []string{msg.SenderId, msg.ReceiverId} // make a sorted array of rec and sender
	// 		sort.Strings(arr)
	//      hasher.Write(arr[0] + arr[1]);
	//      col := hex.EncodeToString(hasher.Sum(nil));
	// 		msg := h.Message_buf[i]
	//
	//
	// 		msgarr := colNames[col] // so that whoever is the sender they end up stored in the same collection
	// 		if msgarr != nil {
	// 			msgarr = append(msgarr, msg)
	// 		} else {
	// 			msgarr = make([]message, 1)
	// 			msgarr = append(msgarr, msg)
	// 		}
	// 		colNames[col] = msgarr
	// 	}
	// 	keys := make([]string, 0, len(colNames))
	// 	for k,_ := range colNames {
	// 		keys = append(keys, k)
	// 	}
	// 	batch := h.FireClient.Batch()
	// 	modBatch := h.FireClient.Batch()
	// 	for k := 0; k < len(keys); k++ {
	// 		col := h.FireClient.Collection(keys[k])
	// 		for i := 0; i < len(colNames[keys[k]]); i++ {
	// 			mm := colNames[keys[k]][i]
	// 			if mm.MsgType == MessageDeleivered || mm.MsgType == MessageRead {
	// 				refs := col.Where("Id", "==", msg.Id).Documents(context.Background())
	// 				for {
	// 					doc, err := refs.Next()
	// 					if err != iterator.Done {
	// 						upd := []firestore.Update{
	// 							{Path: "state", Value: int(mm.MsgType)},
	// 						}
	// 						modBatch.Update(doc.Ref, upd)
	// 					} else {
	// 						break
	// 					}
	// 				}

	// 			}
	// 			batch.Set(col.NewDoc(), mm)
	// 		}

	// 		// job,error := h.fireClient.BulkWriter(context.Background()).Create(h.fireClient.Doc("messages/"+keys[k]),colNames[keys[k]]);
	// 		// results,err := job.Results();

	// 	}
	// 	_, upderr := modBatch.Commit(context.Background())
	// 	_, err := batch.Commit(context.Background())
	// 	if err != nil {
	// 		fmt.Printf("Failed to write batch messages to db %s\n", err.Error())
	// 	}
	// 	if upderr != nil {
	// 		fmt.Printf("Failed to update batch messages to db %s\n", err.Error())

	// 	}
	// } else {
	// 	if msg.MsgType != MessageRead && msg.MsgType != MessageDeleivered && msg.MsgType != MessageReceived {
	// 		h.Message_buf = append(h.Message_buf, msg)

	// 	}
	// }
}
func (h Hub) HandleLoginOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "POST")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,access-control-allow-origin,authorization,clientid,receiverid")
	fmt.Fprintf(w, "Hello")
}
func (h Hub) HandleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	perr := r.ParseMultipartForm(2 << 10)
	if perr != nil {
		fmt.Println("Failed to parse multipart form : " + perr.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")
	if email == "" || password == "" {
		fmt.Println("empty email and/or password field" + perr.Error())
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	u, err := h.FireClient.Collection("users").Where("Email", "==", email).Documents(r.Context()).GetAll()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		fmt.Printf("Error getting users from database %s\n", err.Error())
	}
	var user FullUser
	if len(u) > 0 {
		u[0].DataTo(&user)
		hasher := sha256.New()
		hasher.Write([]byte(user.Password))
		passhash := hasher.Sum(nil)
		if hex.EncodeToString(passhash[:]) == password {
			uid := user.Acc_id
			t, _ := h.TokenManager.GenerateToken(uid)
			fmt.Fprintf(w, `{"error":%d,"id":"%s","token":"%s","expiresAt":%d}`, CHAT_APP_OK, uid, t, time.Now().Add(24*10*time.Hour).Second())
		} else {
			fmt.Printf("Login : Incorrect password : Given hash : %s\n Real hash : %s\n", password, hex.EncodeToString(passhash))
			fmt.Fprintf(w, `{"error":%d}`, INCORRECT_PASSWORD)
		}
	} else {
		fmt.Fprintf(w, `{"error":%d}`, NO_ACCOUNT)
	}

}
func (h Hub) HandleSyncRequestOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "POST")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,access-control-allow-origin,authorization,clientid,receiverid")
	fmt.Fprintf(w, "Hello")
}
func buf2LE(data []byte) []byte {
	tmp := uint32(0)
	bec := make([]byte, 4)
	for f := 0; f < len(data); f = f + 4 {
		tmp = binary.LittleEndian.Uint32(data[f : f+4])
		binary.BigEndian.PutUint32(bec, tmp)
		copy(data[f:f+4], bec)
	}
	return data
}
func msg2LE(msg client.Message) {
	buf2LE(msg.SenderId)
	buf2LE(msg.ReceiverId)
	buf2LE(msg.AuthKey)
	buf2LE(msg.Payload)
}
func (h Hub) HandleMessages(c client.Client) {
	for {
		select {
		case msg := <-c.Outgoing:
			// msg2LE(*msg)
			receiveruuid := hex.EncodeToString(msg.ReceiverId)
			senderuuid := hex.EncodeToString(msg.SenderId)
			fmt.Printf("Hub : received message from %s to : %s ,type : %d,payload length :%d\n", senderuuid, receiveruuid, msg.MsgType, len(msg.Payload))
			receiver := h.Clients[receiveruuid]
			sender := h.Clients[senderuuid]
			var resmsg client.Message // return to client that the message has been successfully processed by the server
			resmsg.Timestamp = uint64(time.Now().UnixMilli())
			resmsg.AuthKey = msg.AuthKey
			resmsg.PayloadLength = uint16(1)
			resmsg.Id = msg.Id
			resmsg.SenderId = bytes.Repeat([]byte{0x00, 0x00}, 16)
			resmsg.ReceiverId = msg.SenderId

			var m message //
			m.Id = msg.Id
			m.MsgType = msg.MsgType
			m.ReceiverId = msg.ReceiverId
			m.SenderId = msg.SenderId
			m.Timestamp = msg.Timestamp
			m.Payload = append(msg.Iv, msg.Payload...)
			if msg.MsgType == Text || msg.MsgType == Image || msg.MsgType == Voice {
				resmsg.Payload = msg.ReceiverId
			}

			if receiver != nil {
				fmt.Println("receiver " + receiveruuid + " connected !")
				msg.AuthKey = receiver.AuthKey
				decrypted := structureMessage(*msg)
				resmsg.MsgType = MessageDeleivered
				//message sent confirmation to client
				m.State = MessageDeleivered
				// if msg.MsgType == MessageRead {
				// 	resmsg.MsgType = MessageReceived

				// }
				resmsg.Payload = msg.ReceiverId

				receiver.SendMessage(decrypted)
			} else {
				if msg.MsgType == Text || msg.MsgType == Voice || msg.MsgType == Image {
					arr := []string{senderuuid, receiveruuid}
					sort.Strings(arr)
					m.State = MessageReceived
					resmsg.MsgType = MessageReceived
				}
			}
			if resmsg.MsgType != MessageRead { // message sent confirmation ,currently not confirming the receival of message state messages
				sender.SendMessage(structureMessage(resmsg))
			}
			h.StoreMessage(m)
		}
	}
}

type User struct {
	User_name     string `json:"user_name"`
	Acc_id        string `json:"user_id"`
	Public        string `json:"public"`
	Profile_photo string `json:"profile_photo"`
}

func (h Hub) HandleFileOptionsRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "POST")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,content-length,access-control-allow-origin,authorization,clientid,receiverid")
	fmt.Fprintf(w, "Hello")
}
func (h Hub) HandleFileRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "POST")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,access-control-allow-origin,authorization,clientid,receiverid")
	// fmt.Fprintf(w, "Hello")
	id := mux.Vars(r)["id"]
	fobj, err := h.FireClient.Collection("files").Where("FileId", "==", id).Documents(r.Context()).GetAll()
	if err != nil {
		fmt.Printf("FileRequest : Failed to get object from firestore %s", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	b, berr := h.StorageClient.DefaultBucket()
	if berr != nil {
		fmt.Printf("FileRequest : Failed to acquire bucket %s", berr.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	url := fobj[0].Data()["Url"].(string)
	// url ,e := fobj[0].DataAt("Url").(string);
	obj := b.Object(url)
	// attrs,aerr := obj.Attrs(r.Context());
	reader, rerr := obj.NewReader(r.Context())
	if rerr != nil {
		fmt.Printf("FileRequest : Failed to get reader from object with name %s :  %s", url, rerr.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	// buftosend := make([]byte,attrs.Size);
	// buftosend, rerr := ioutil.ReadAll(reader)
	if rerr != nil {
		fmt.Printf("FileRequest : Failed to read from object with name %s : %s", url, err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	t := fobj[0].Data()["type"].(string)
	// w.WriteHeader(200)
	fmt.Println("got file type " + t)
	w.Header().Set("Content-Type", t)
	io.Copy(w, reader)
	// w.Write(buftosend)

}

func (h *Hub) ServeWs(w http.ResponseWriter, r *http.Request) {
	tmpid := r.URL.Query().Get("id")
	fmt.Println("WS request received with tmpid : " + tmpid)
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	var upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("An error occured while upgrading to websockets protocol : " + err.Error())
		fmt.Println("Info : " + r.RemoteAddr)
		conn.Close()
		return

	}
	c := h.Clients[h.Tmpids[tmpid]]
	c.Conn = conn
	go c.GetMessage()
	go c.HandleMessage()
	go h.HandleMessages(*c)
}
func HandleChatOptionsRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "GET")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,access-control-allow-origin,authorization,clientid,tmpid")
	fmt.Fprintf(w, "Hello")

}
func (h Hub) HandleWSOptionsRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "GET")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,access-control-allow-origin")
	fmt.Fprintf(w, "Hello")
}

type Signup_data struct {
	Email         string `firestore:"Email"`
	Password      string `firestore:"Password"`
	Profile_photo string `firestore:"Profile_photo"`
	User_name     string `firestore:"User_name"`
	Public        string `firestore:"Public"`
	Acc_id        string `firestore:"Acc_id"`
}

func (h Hub) CheckToken(token string) bool {
	return true // for now
}
func (h Hub) HandleSignupOtions(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "POST")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,access-control-allow-origin")
	fmt.Fprintf(w, "Hello")

}
func (h Hub) HandleUpload(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "POST")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,access-control-allow-origin,authorization,clientid")
	token := strings.Split(r.Header.Get("Authorazation"), " ")[1]

	if !h.CheckToken(token) {
		http.Error(w, "Unauthorized : Token absent or Invalid", http.StatusUnauthorized)
		return
	}
	ClientId := r.Header.Get("ClientId")
	if !h.CheckClient(ClientId) {
		http.Error(w, "Unauthorized : Invalid Client Id", http.StatusUnauthorized)
		return
	}
	url, uerr := h.UploadFile(r)
	if uerr != nil {
		fmt.Printf("Failed to upload file : %s", uerr.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
	// Parse_err := r.ParseMultipartForm(10 << 20)
	// if Parse_err != nil {
	// 	fmt.Printf("Could not parse form : %v", Parse_err)
	// }
	// file, header, err := r.FormFile("file")
	// if err != nil {
	// 	fmt.Printf("Error in FormFile() %s", err.Error())
	// }
	// if header.Size > 2<<20*20 {
	// 	http.Error(w, "File too big", http.StatusForbidden)
	// 	return
	// }

	// bucket, _ := h.StorageClient.Bucket(ClientId + "-files")
	// obj := bucket.Object(header.Filename)
	// writer := obj.NewWriter(r.Context())
	// // fbytes := make([]byte,header.Size);
	// // file.Read(fbytes);
	// // writer.Write(fbytes);
	// io.Copy(writer, file)
	// writerr := writer.Close()
	// if writerr != nil {
	// 	fmt.Printf("failed to write to remote object %s", writerr.Error())
	// }
	// attrs, _ := obj.Attrs(r.Context())
	// mlink := attrs.MediaLink
	// w.Header().Add("content-type", "application/json")
	fmt.Fprintf(w, `{"error":%d,"url":"%s"}`, CHAT_APP_OK, "http://localhsot:8080/file/"+url)

}
func (h Hub) HandleUploadOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "POST")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,access-control-allow-origin,authorization,clientid")
	fmt.Fprintf(w, "Hello")
}
func (h Hub) UploadFile(r *http.Request) (string, error) {
	file, header, file_err := r.FormFile("file")
	if file_err != nil {
		fmt.Printf("Error parsing file big %s\n", file_err.Error())

		return "", errors.New(fmt.Sprintf("Error parsing file :%s", file_err.Error()))
	}
	if header.Size > 2<<20*20 {
		fmt.Printf("File too big %d\n", header.Size)
		// http.Error(w, "File too big", http.StatusBadRequest)
		return "", errors.New("File too big")
	}
	fbytes := make([]byte, header.Size)
	file.Read(fbytes)

	storageBucket, berr := h.StorageClient.DefaultBucket()
	if berr != nil {
		// http.Error(w, "Internal server error", http.StatusInternalServerError)
		return "", errors.New(fmt.Sprintf("Failed to get storage bucket %s\n", berr.Error()))
	}
	fname := header.Filename + randString(15)
	obj := storageBucket.Object(fname)
	writer := obj.NewWriter(r.Context())
	io.Copy(writer, file)
	// _,e := ioutil.ReadAll(io.TeeReader(file,writer)); if e!=nil{
	// 	log.Fatalf("Error reading from file %s",e.Error())
	// 	http.Error(w,"Internal server Error",http.StatusInternalServerError);
	// 	return;
	// }
	// attrs,_ := obj.Attrs(r.Context());
	// dlink := attrs.MediaLink;
	writerr := writer.Close()
	if writerr != nil {
		// fmt.Printf("Failed to write to remote object %s\n", writerr.Error())
		// http.Error(w, "Internal server error ", http.StatusInternalServerError)
		return "", errors.New(fmt.Sprintf("Failed to write to remote object %s\n", writerr.Error()))

	}
	// attrs, _ := obj.Attrs(r.Context());
	imgid := randString(20)
	var t string

	ext := strings.ToLower(header.Filename[strings.LastIndex(header.Filename, ".")+1:])
	t = "application/" + ext
	if ext == "png" || ext == "jpeg" {
		t = "image/" + ext
	}
	if ext == "mp3" || ext == "m4a" {
		t = "audio/" + ext
	}
	d := map[string]interface{}{}
	d["FileId"] = imgid
	d["Url"] = fname
	d["type"] = t
	_, inerr := h.FireClient.Collection("files").NewDoc().Set(r.Context(), d)
	if inerr != nil {
		return "", errors.New(fmt.Sprintf("Failed to write to database %s\n", inerr.Error()))
	}
	return imgid, nil
	// userdata.Profile_photo = mlink.MediaLink
}
func (h Hub) HandleSignup(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "POST")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,access-control-allow-origin")
	// r.ParseMultipartForm(20 << 30)
	// body, err := ioutil.ReadAll(r.Body)
	// if err != nil {
	// 	log.Fatal("Error while reading body data")
	// }
	// var data Signup_data
	// err = json.Unmarshal(body, &data)
	// if err != nil {
	// 	log.Fatal("Error while unmarshal ! ")
	// }

	// userdata := &Signup_data{
	// 	email:     r.FormValue("email"),
	// 	password:  r.FormValue("password"),
	// 	user_name: r.FormValue("user_name"),
	// 	public:    r.FormValue("public"),
	// }
	var userdata Signup_data
	userdata.Email = r.FormValue("email")
	userdata.Password = r.FormValue("password")
	userdata.Public = r.FormValue("public")
	userdata.User_name = r.FormValue("user_name")
	possibleConfilct, _ := h.FireClient.Collection("users").Where("Email", "==", userdata.Email).Documents(r.Context()).GetAll()
	if len(possibleConfilct) != 0 {
		// handle Confilct
		obj := fmt.Sprintf(`{"error":%d}`, EMAIL_USED)
		w.Header().Add("content-type", "application/json")
		fmt.Fprintf(w, obj)
		return
	}
	acc_id := sha256.Sum256([]byte(userdata.Email + userdata.User_name))
	userdata.Acc_id = hex.EncodeToString(acc_id[:])
	file, header, file_err := r.FormFile("image")
	if file_err != nil {
		fmt.Printf("Error parsing file big %s\n", file_err.Error())
		http.Error(w, "Error parsing file", http.StatusBadRequest)
		return
	}
	if header.Size > 2<<20*20 {
		fmt.Printf("File too big %d\n", header.Size)
		http.Error(w, "File too big", http.StatusBadRequest)
		return
	}
	fbytes := make([]byte, header.Size)
	file.Read(fbytes)

	storageBucket, berr := h.StorageClient.DefaultBucket()
	if berr != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		fmt.Printf("Failed to get storage bucket %s\n", berr.Error())
	}
	ext := strings.ToLower(header.Filename[strings.LastIndex(header.Filename, ".")+1:])
	obj := storageBucket.Object("capp_files/" + header.Filename[:strings.LastIndex(header.Filename, ".")] + randString(15) + "." + ext)

	writer := obj.NewWriter(r.Context())
	writer.ContentType = "image/" + ext
	file, oerr := header.Open()
	if oerr != nil {
		fmt.Println("Error opening file " + oerr.Error())
	}
	imgbytes := make([]byte, header.Size)
	haveread, rerr := file.Read(imgbytes)
	// written, werr := io.Copy(writer, file)
	written, _ := writer.Write(imgbytes)
	if rerr != nil {
		fmt.Println("Error reading from file " + rerr.Error())
	}
	fmt.Println(hex.Dump(imgbytes))
	fmt.Printf("We read %d : %d and wrote %d bytes and real size%d\n ", haveread, len(imgbytes), written, header.Size)

	// fmt.Printf("File Contents \n%s\n", hex.Dump(imgbytes))
	// _,e := ioutil.ReadAll(io.TeeReader(file,writer)); if e!=nil{
	// 	log.Fatalf("Error reading from file %s",e.Error())
	// 	http.Error(w,"Internal server Error",http.StatusInternalServerError);
	// 	return;
	// }
	// attrs,_ := obj.Attrs(r.Context());
	// dlink := attrs.MediaLink;
	writerr := writer.Close()
	if writerr != nil {
		fmt.Printf("Failed to write to remote object %s\n", writerr.Error())
		http.Error(w, "Internal server error ", http.StatusInternalServerError)
		return
	}
	mlink, _ := obj.Attrs(r.Context())
	imgid := randString(20)
	d := map[string]interface{}{}
	d["FileId"] = imgid
	d["Url"] = mlink.Name
	d["type"] = "image/" + ext
	_, inerr := h.FireClient.Collection("files").NewDoc().Set(r.Context(), d)
	if inerr != nil {
		fmt.Printf("HandleSignUp : Failed to write image data to firestore %s", inerr.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	userdata.Profile_photo = imgid
	_, inserterror := h.FireClient.Collection("users").NewDoc().Set(r.Context(), userdata)
	if inserterror != nil {
		// handle Insertion error
		fmt.Printf("Failed to insert to firestore users  %s\n", inserterror.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	t, err := h.TokenManager.GenerateToken(userdata.Acc_id)
	if err != nil {
		fmt.Printf("Failed to generate token :%s\n", err.Error())
		res := fmt.Sprintf(`{"error":%d,"message":"%s"}`, INTERNAL_ERROR, "Unable to generate token please try to login ")
		w.Header().Add("content-type", "application/json")
		fmt.Fprintf(w, res)
	}

	json_obj := fmt.Sprintf(`{"error":%d,"id":"%s","token":"%s","expiresAt":"%s"}`, CHAT_APP_OK, userdata.Acc_id, t, time.Now().Add(10*24*time.Hour).String())
	w.Header().Add("content-type", "application/json")
	fmt.Fprintf(w, json_obj)
}
func (h Hub) HandleUsersOptionsRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "POST")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,access-control-allow-origin,authorization,clientid")
	fmt.Fprintf(w, "Hello")
}
func (h Hub) HandleUsersRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "POST")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,access-control-allow-origin,authorization,clientid")

	accounts, err := h.FireClient.Collection("users").Select("User_name", "Acc_id", "Public", "Profile_photo").Documents(r.Context()).GetAll()
	if err != nil {
		fmt.Printf("Error getting users %s", err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	var users []User
	for i := 0; i < len(accounts); i++ {
		var user User

		accounts[i].DataTo(&user)
		users = append(users, user)
	}
	fmt.Print("users request received : \n")
	// s, _ := json.Marshal(users)

	fmt.Printf(" count:%d", len(accounts))
	json.NewEncoder(w).Encode(users)

}
func (h Hub) handleMessagesRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "POST")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,access-control-allow-origin,authorization,clientid")
	cid := r.Header.Get("ClientId")
	token := strings.Split(r.Header.Get("Authorization"), " ")[1]
	receiver := r.Header.Get("ReceiverID")

	if !h.CheckClient(cid) {
		http.Error(w, "Invalid Client Id", http.StatusForbidden)
		return
	}
	if !h.CheckToken(token) {
		http.Error(w, "Invalid or absent Token ", http.StatusUnauthorized)
		return
	}
	type message struct {
		Id        uint32
		Authkey   string
		Sender    string
		Receiver  string
		Timestamp uint64
		Payload   []byte
	}
	arr := []string{cid, receiver}
	sort.Strings(arr)
	m := h.FireClient.Collection(arr[0]+"-"+arr[1]+"-messages").Where("ReceiverId", "==", receiver).Documents(r.Context())
	var msgs []message
	for {
		var msg message
		doc, done := m.Next()
		if done != iterator.Done {
			doc.DataTo(&msg)
			msgs = append(msgs, msg)
		} else {
			break
		}
	}
	json.NewEncoder(w).Encode(msgs)
}
func (h Hub) HandleChatOptionsRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "GET")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,access-control-allow-origin,authorization,clientid,tmpid")
	fmt.Fprintf(w, "Hello")

}
func (h *Hub) HandleChatRequest(w http.ResponseWriter, r *http.Request) {
	// auth := r.Header["Authorization"];;
	// token := strings.Split(auth[0]," ")[1];
	fmt.Println("Chat request received")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	// s := `[
	// 	{
	// 		"user_name": "abdoDZ98",
	// 		"id": "22906912ee7b98b56043d27533e2ac4585b6cc9325531cd56d294216997e7cd0",
	// 		"state": "n"
	// 	},
	// 	{
	// 		"user_name": "Bachir98",
	// 		"id": "6a3623353c029bb29a0bb2fb8c1c5971f1a12bc72a64633f16869c4d4110f4e8",
	// 		"state": "n"
	// 	}
	// ]`
	cid := r.Header.Get("ClientId")
	tmpid := r.Header.Get("tmpid")
	if !h.CheckClient(cid) {
		http.Error(w, "Unauthorized : Invalid ClientID", http.StatusUnauthorized)
		return
	}
	fmt.Println("new Client Connected with id : " + cid + "and tmpid" + tmpid)

	h.Tmpids[tmpid] = cid
	c := &client.Client{
		AuthKey:  make([]byte, 32),
		EncKey:   nil,
		Incoming: make(chan *client.Message),
		Uuid:     cid,
		Outgoing: make(chan *client.Message),
	}

	c.MainPrime = h.Mp
	h.Clients[cid] = c
	for cl := range h.Clients {
		if cl != cid {
			p, _ := hex.DecodeString(cid)
			cc := h.Clients[cl]
			ucmsg := &client.Message{
				Id:            0,
				Timestamp:     uint64(time.Now().UnixMilli()),
				MsgType:       UserConnected,
				SenderId:      bytes.Repeat([]byte{0x00}, 32),
				ReceiverId:    []byte(cc.Uuid),
				PayloadLength: 32,
				Payload:       p,
			}
			cc.SendMessage(structureMessage(*ucmsg))
		}

	}
	// json.NewEncoder(w).Encode(users)
	fmt.Fprint(w, "[{}]")
}
func (h Hub) HandlePendingMessagesRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "POST")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,access-control-allow-origin,authorization,clientid")
	cid := r.Header.Get("ClientId")
	token := strings.Split(r.Header.Get("Authorization"), " ")[1]
	receiver := r.Header.Get("ReceiverID")

	if !h.CheckClient(cid) {
		http.Error(w, "Invalid Client Id", http.StatusForbidden)
		return
	}
	if !h.CheckToken(token) {
		http.Error(w, "Invalid or absent Token ", http.StatusUnauthorized)
		return
	}
	type message struct {
		id        uint32
		authkey   string
		sender    string
		receiver  string
		timestamp uint64
		payload   string
	}
	arr := []string{cid, receiver}
	sort.Strings(arr)
	m := h.FireClient.Collection(arr[0]+"-"+arr[1]+"-messages").Where("ReceiverId", "==", receiver).Where("State", "!=", MessageRead).Documents(r.Context())
	var msgs []message
	for {
		var msg message
		doc, done := m.Next()
		if done != iterator.Done {
			doc.DataTo(&msg)
			msgs = append(msgs, msg)
		}
	}
}
func (h Hub) HandlePendingMessagesRequestOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Allow", "POST")
	w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Add("Access-Control-Allow-Headers", "content-type,access-control-allow-origin,clientid,authorization,receiverid")
	fmt.Fprintf(w, "Hello")
}
