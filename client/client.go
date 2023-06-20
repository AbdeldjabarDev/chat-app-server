package client

import (
	"container/list"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"time"

	"cloud.google.com/go/firestore"
	"firebase.google.com/go/storage"
	"github.com/gorilla/websocket"
)

const (
	Text              = byte(0)
	Image             = byte(1)
	Voice             = byte(2)
	MessageDeleivered = byte(3)
	MessageRead       = byte(4)
	EncKeyRequest     = byte(5)
	AuthKeyRequest    = byte(6)
	EncKeyResponse    = byte(7)
	AuthKeyResponse   = byte(8)
	UserTyping        = byte(10)
	UserConnected     = byte(11)
)

type Message struct {
	Iv            []byte
	ver           byte
	Id            uint32
	Timestamp     uint64
	MsgType       byte
	PayloadLength uint16
	Reserved      byte
	AuthKey       []byte
	SenderId      []byte
	ReceiverId    []byte
	Payload       []byte
}

func destructureMessage(data []byte, iv []byte) (msg *Message) {

	mssg := new(Message)
	mssg.ver = data[0]
	mssg.Id = binary.LittleEndian.Uint32(data[1:5])
	mssg.AuthKey = data[5:37]
	mssg.SenderId = data[37:69]
	mssg.ReceiverId = data[69:101]
	mssg.Timestamp = binary.BigEndian.Uint64(data[101:109])
	mssg.MsgType = data[109]
	mssg.PayloadLength = binary.LittleEndian.Uint16(data[110:112])
	// mssg.Reserved = data[112]
	mssg.Payload = data[112:]
	mssg.Iv = iv
	fmt.Printf("dm : sId is : %x\n", mssg.SenderId)
	fmt.Printf("dm : rId is : %x\n", mssg.ReceiverId)
	fmt.Printf("dm : type is : %d\n", mssg.MsgType)

	return mssg
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

type Client struct {
	Conn *websocket.Conn
	// send chan []byte;
	AuthKey     []byte
	EncKey      []byte
	Uuid        string
	Incoming    chan *Message
	Outgoing    chan *Message
	message_buf list.List
	MainPrime   *big.Int
}

func structureMessage(msg Message) []byte {
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
	data[19] = byte(1)
	copy(data[19:23], uint322bin(msg.Id))
	copy(data[23:55], msg.AuthKey)
	copy(data[55:87], msg.SenderId)
	copy(data[87:119], msg.ReceiverId)
	copy(data[119:127], uint642bin(msg.Timestamp))
	data[127] = msg.MsgType
	copy(data[128:130], uint162bin(msg.PayloadLength))
	// data[130] = byte(0)
	copy(data[130:], msg.Payload)
	fmt.Printf("sm : final message length : %d", len(data))
	return data

}

type Hub struct {
	clients       map[string]*Client
	numClients    int
	mqueue        chan *Message
	tmpids        map[string]string
	fireClient    firestore.Client
	storageClient storage.Client
	message_buf   []Message
	accounts      []FullUser
}
type FullUser struct {
	email         string `json:"email"`
	password      string `json:"password"`
	profile_photo string `json:"profile_photo`
	public        string `json:"public"`
	user_name     string `json:"user_name"`
}

func (c *Client) HandleMessage() {
	for {
		select {
		case msg := <-c.Incoming:
			// fmt.Printf("Got message from client : %s with type %d", c.uuid, msg.msgType)
			switch msg.MsgType {
			case MessageRead:
				var id uint32
				binary.BigEndian.PutUint32(msg.Payload, id)
				fmt.Println("Message read received : receiver " + hex.EncodeToString(msg.ReceiverId) + "and id : " + fmt.Sprintf("%d", id))
				c.Outgoing <- msg
				break
			case Image:
			case Voice:
			case Text:
				fmt.Println("Text message received redirecting it to hub")
				c.Outgoing <- msg
				break
			case EncKeyRequest:
				var result = new(big.Int)
				var trueresult = new(big.Int)
				b, _ := rand.Int(rand.Reader, big.NewInt(100000))
				g := big.NewInt(3)
				var gamodb = new(big.Int)
				var gbmodp = new(big.Int)
				gamodb.SetBytes(msg.Payload)
				gbmodp.SetBytes(g.Exp(g, b, c.MainPrime).Bytes())
				result.SetBytes(g.Exp(gamodb, b, c.MainPrime).Bytes())
				fmt.Println("gamodp : " + gamodb.Text(16) + "\ngbmodp : " + gbmodp.Text(16))
				trueresult = result.Mod(result, c.MainPrime)
				// bi.Mod(&bi, &mainPrime)
				fmt.Println("got enckey :  " + trueresult.Text(16))
				hasher := sha256.New()
				// hasher.Reset()
				k, _ := hex.DecodeString(trueresult.Text(16))
				hasher.Write(k)
				c.EncKey = hasher.Sum(nil)
				ResMsg := new(Message)
				ResMsg.Id = 2
				ResMsg.AuthKey = make([]byte, 32)
				ResMsg.SenderId = make([]byte, 32)
				ResMsg.ReceiverId = make([]byte, 32)
				ResMsg.MsgType = byte(EncKeyResponse)
				ResMsg.Payload = gbmodp.Bytes()
				ResMsg.Timestamp = uint64(time.Now().UnixNano() / 1000)
				ResMsg.PayloadLength = uint16(len(gbmodp.Bytes()))
				// msgData := structureMessage(*ResMsg)
				data := make([]byte, 145)
				copy(data[0:4], uint322bin(ResMsg.Id))
				copy(data[4:36], ResMsg.AuthKey)
				copy(data[36:68], ResMsg.SenderId)
				copy(data[68:100], ResMsg.ReceiverId)
				copy(data[100:108], uint642bin(ResMsg.Timestamp))
				data[108] = ResMsg.MsgType
				copy(data[109:111], uint162bin(ResMsg.PayloadLength))
				data[111] = byte(0)
				copy(data[112:], ResMsg.Payload)
				fmt.Println("msg data : " + hex.EncodeToString(data))
				c.Conn.WriteMessage(websocket.BinaryMessage, data)
				fmt.Println("responded to enckey request")
				break
			case AuthKeyRequest:
				fmt.Printf("authkey request from client : %s\n", c.Uuid)
				ak := append([]byte(c.Uuid+":"), c.EncKey...)
				hash := sha256.Sum256(ak)
				rid, _ := hex.DecodeString(c.Uuid)
				copy(ak, hash[:])
				ResMsg := new(Message)
				ResMsg.Id = 2
				ResMsg.AuthKey = make([]byte, 32)
				ResMsg.SenderId = make([]byte, 32)
				ResMsg.ReceiverId = rid
				ResMsg.MsgType = byte(AuthKeyResponse)
				ResMsg.Payload = hash[:]
				ResMsg.Timestamp = uint64(time.Now().UnixNano() / 1000)
				ResMsg.PayloadLength = uint16(len(ak))
				msgData := c.EncryptData(structureMessage(*ResMsg))
				// fmt.Println("msg data : " + hex.EncodeToString(msgData))
				c.Conn.WriteMessage(websocket.BinaryMessage, msgData)
				fmt.Printf("Responded to auth key request with auth key : %x\n", ak)
				c.AuthKey = ak

				break
			}

			break
		}
	}

}
func (c Client) DecryptData(data []byte, iv []byte) []byte {

	block, err := aes.NewCipher(c.EncKey)
	if err != nil {
		fmt.Println("Failed to create block " + err.Error())
	}
	// encrypter := cipher.NewCBCEncrypter(block, iv)
	// zeroesdecrypter := cipher.NewCBCDecrypter(block, iv)
	decrypter := cipher.NewCBCDecrypter(block, iv)
	// goencrypted := make([]byte, 32)
	// godecrypted := make([]byte, 32)
	// encrypter.CryptBlocks(goencrypted, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// zeroesdecrypter.CryptBlocks(godecrypted, goencrypted)
	// fmt.Printf("goencrypted :  %x length : %d\n", goencrypted, len(goencrypted))
	// fmt.Printf("godecrypted :  %x length : %d\n", godecrypted, len(godecrypted))
	// fmt.Printf("ciphertext : %x\n", data[4:])
	result := make([]byte, 112)
	// tobdecrypted := make([]byte, 112)
	databuf := make([]byte, 112)
	copy(databuf, data[18:130])
	tmp := uint32(0)
	bec := make([]byte, 4)
	for f := 0; f < len(databuf); f = f + 4 {
		tmp = binary.LittleEndian.Uint32(databuf[f : f+4])
		binary.BigEndian.PutUint32(bec, tmp)
		copy(databuf[f:f+4], bec)
	}
	fmt.Printf("decrypting for client %s\n with key %x : and iv %x \n", c.Uuid, c.EncKey, iv)
	if len(databuf) < 80 {
		fmt.Printf("ciphertext : %x length : %d\n", databuf, len(databuf))
	}
	fmt.Printf("ciphertext : %x.....%x length : %d\n", databuf[:20], databuf[len(databuf)-20:], len(databuf))
	decrypter.CryptBlocks(result, databuf)
	if len(result) < 80 {
		fmt.Printf("plaintext : %x length : %d\n", result, len(result))
	}
	for f := 0; f < len(result); f = f + 4 {
		tmp = binary.LittleEndian.Uint32(result[f : f+4])
		binary.BigEndian.PutUint32(bec, tmp)
		copy(result[f:f+4], bec)
	}
	fmt.Printf("plaintext : %x.....%x\n length :%d", result[:20], result[len(result)-20:], len(result))
	return append(result, data[130:]...)
}
func (c Client) DecryptMessage(data []byte) *Message {
	if c.EncKey == nil {
		fmt.Println("Client doesn't have enc key ")
		return destructureMessage(data, nil)
	} else {

		// l := binary.LittleEndian.Uint16(data[2:4])
		// fmt.Print("data words ")
		// for f := 4; f < len(data); f = f + 4 {
		// 	fmt.Print(binary.LittleEndian.Uint32(data[f : f+4]))
		// 	fmt.Print(", ")
		// }
		// fmt.Println("")
		// fmt.Printf("encrypted : "+hex.EncodeToString(data)+"length : %d\n", (len(data)))
		// i := binary.LittleEndian.Uint16(data[0:2])
		tmp := uint32(0)
		bec := make([]byte, 4)
		iv := data[2:18]
		for f := 0; f < len(iv); f = f + 4 {
			tmp = binary.LittleEndian.Uint32(iv[f : f+4])
			binary.BigEndian.PutUint32(bec, tmp)
			copy(iv[f:f+4], bec)
		}
		// keybytes := make([]byte, 32)
		// bkey, _ := hex.DecodeString(c.encKey)
		// hash := sha256.Sum256(bkey)
		// copy(keybytes, hash[:])
		// block, _ := aes.NewCipher(keybytes)
		// encrypter := cipher.NewCBCEncrypter(block, iv)
		// dt, _ := hex.DecodeString("000000000000000000000000000000000000000000000000000000000000000000000000a9ea5fe06b83c5a014b306b881006d1cd3edf7204c4bf4463c4ca7bc9f207d5900000000000000000000000000000000000000000000000000000000000000000000018718ef6dbc06200000")
		// encresult := make([]byte, len(dt))
		// decresult := make([]byte, len(encresult))
		// fmt.Print("example dec : ")
		// encrypter.CryptBlocks(encresult, dt)
		// decrypter.CryptBlocks(decresult, encresult)
		// for f := 4; f < len(decresult); f = f + 4 {
		// 	fmt.Print(binary.LittleEndian.Uint32(decresult[f : f+4]))
		// 	fmt.Print(", ")
		// }
		// fmt.Printf("decrypting with key : "+hex.EncodeToString(slice)+"and iv %s %d blocksize : %d keysize %d\n", hex.EncodeToString(iv), len(iv), decrypter.BlockSize(), len(slice))
		result := c.DecryptData(data, iv)
		// fmt.Print("encrypted words :  ")
		// for f := 4; f < len(result); f = f + 4 {
		// 	fmt.Print(binary.LittleEndian.Uint32(result[f : f+4]))
		// 	fmt.Print(", ")
		// }
		// ciphertext := make([]byte, len(data)-4)
		// fmt.Printf("unecrypted data : %x", data)
		// encrypter.CryptBlocks(ciphertext, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		// fmt.Printf(" encrypted bytes : %x", ciphertext)
		// fmt.Println("")
		return destructureMessage(result, iv)
		// return nil
	}
}
func (c *Client) SendMessage(data []byte) {
	// slice := make([]byte, 32)
	// hash := sha256.Sum256([]byte(c.encKey))
	// copy(slice, hash[:])
	// block, _ := aes.NewCipher(slice)
	// i := rand.Intn(8)
	// iv, _ := hex.DecodeString(Ivs[i])

	// dataSlice := make([]byte, len(data)+16-len(data)%16)
	// l := len(dataSlice)
	// if len(data)%16 != 0 {
	// 	fmt.Printf("data %d ,dataSlice %d size is not a multiple of 16 padding it with %d bytes\n", len(data), len(dataSlice), len(data)%16)
	// 	pad := make([]byte, 16-16%len(data))
	// 	copy(dataSlice, data)
	// 	_ = append(dataSlice, pad...)
	// 	fmt.Printf("now dataSlice is %d bytes\n", len(dataSlice))
	// }
	// _ = append(dataSlice, data...)
	// encrypter := cipher.NewCBCEncrypter(block, iv)
	// buftosend := make([]byte, l+4)
	// lbytes := make([]byte, 2)
	// ibytes := make([]byte, 2)
	// fmt.Printf("Sending message with Enckey %x and AuthKey %x and length %d\n", c.encKey, c.authKey, l)
	// binary.BigEndian.PutUint16(lbytes, uint16(l))
	// binary.BigEndian.PutUint16(ibytes, uint16(i))
	// buftosend = append(buftosend, lbytes...)
	// buftosend = append(buftosend, ibytes...)
	// encrypter.CryptBlocks(buftosend[4:], dataSlice)
	c.Conn.SetWriteDeadline(time.Now().Add(1000 * time.Millisecond))
	// fmt.Printf("encrypting data with  size %d i.e %d blocks\n", len(data), len(data)%16)
	buftosend := c.EncryptData(data)
	c.Conn.WriteMessage(websocket.BinaryMessage, buftosend)
}
func (c Client) EncryptData(data []byte) []byte {
	iv := data[2:18]

	fmt.Printf("Encrypting data for client : %s\nwith key : %x ,iv : %x and size %d i.e %d blocks\n", c.Uuid, c.EncKey, iv, len(data), len(data)/16)
	block, _ := aes.NewCipher(c.EncKey)
	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypter.CryptBlocks(data[18:130], data[18:130])
	fmt.Printf("Got ciphertext : \n%x\n", data[18:130])
	buf2LE(data[2:130])
	return data
}
func buf2LE(databuf []byte) {
	tmp := uint32(0)
	bec := make([]byte, 4)
	for f := 0; f < len(databuf); f = f + 4 {
		tmp = binary.BigEndian.Uint32(databuf[f : f+4])
		binary.LittleEndian.PutUint32(bec, tmp)
		copy(databuf[f:f+4], bec)
	}
	return
}
func (c *Client) GetMessage() (err error) {
	for {

		t, msg, err := c.Conn.ReadMessage()
		if err != nil {
			fmt.Printf("Error reading message " + err.Error())
			return err
		}
		if t != websocket.PingMessage && t != websocket.PongMessage {
			realmsg := make([]byte, len(msg))
			copy(realmsg, msg)
			fmt.Println("------------------------------------------------------------------------------")
			fmt.Printf("got msg  : with length : %d\n", len(msg))
			message := c.DecryptMessage(realmsg)
			c.Incoming <- message
		}

	}
}
