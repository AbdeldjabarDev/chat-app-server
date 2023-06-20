package main

import (
	// "encoding/json"
	// "bytes"

	"crypto/sha256"
	"fmt"

	"log"
	"math/big"
	"net/http"

	firebase "firebase.google.com/go"
	"github.com/gorilla/mux"

	//   "firebase.google.com/go/auth"
	client "chat-server/client"
	"context"

	Hub "chat-server/hub"

	"google.golang.org/api/option"
)

var Ivs []string = []string{
	"101112131415161718191a1b1c1d1e1f",
	"ab11121ed415161718191afb1c1d1e1f",
	"10ee121314ef16aa181cca1b1c1d1e1f",
	"10ef12ca141516ff18191a1b1c1d1e1f",
	"1fa11213fe151617ee191a1b1c1d1e1f",
	"1bb11aa314ac51ef718191a1b1c1d1e1f",
	"1afe1b13141d1e1718d91aeb1cad1e1f",
	"af11cd13ea15161718ee1a1b1c1d1e1f",
}
var mainPrime *big.Int = new(big.Int)

// var g *big.Int = big.NewInt(3)

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
const (
	CHAT_APP_OK        = 0
	EMAIL_USED         = 5
	INTERNAL_ERROR     = 10
	INCORRECT_PASSWORD = 2
	INVALID_EMAIL      = 3
	INVALID_CODE       = 4
	NO_ACCOUNT         = 6
)

func main() {
	opt := option.WithCredentialsFile("C:/Users/LEGION/Desktop/complete-kite-320815-firebase-adminsdk-v9mts-06e2a5a5a4.json")
	app, err := firebase.NewApp(context.Background(), &firebase.Config{
		StorageBucket: "complete-kite-320815.appspot.com",
	}, opt)

	if err != nil {
		log.Fatalf("error initializing app: %s", err.Error())
	}
	firestoreClient, cerr := app.Firestore(context.Background())

	if cerr != nil {
		log.Fatalf("Failed initializing firestore client %v", err)
	}
	storageClient, serr := app.Storage(context.Background())
	if serr != nil {
		log.Fatalf("Failed initializing storage client %v", err)

	}
	singingkey := sha256.Sum256([]byte("Hello Chat App"))
	tm, _ := Hub.NewTokenManager(singingkey[:], 24*10*60, firestoreClient.Collection("tokens"))
	mainPrime.SetString("5210644015679228794060694325390955853335898483908056458352183851018372555735221", 10)
	hub := &Hub.Hub{
		Clients:       make(map[string]*client.Client),
		Tmpids:        map[string]string{},
		Mqueue:        make(chan *Hub.Message),
		FireClient:    *firestoreClient,
		StorageClient: *storageClient,
		Mp:            mainPrime,
		TokenManager:  *tm,
	}

	router := mux.NewRouter()
	router.HandleFunc("/chat", hub.HandleChatRequest).Methods("POST")
	router.HandleFunc("/chat", hub.HandleChatOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/ws", hub.ServeWs).Methods("GET")
	router.HandleFunc("/ws", hub.HandleWSOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/signup", hub.HandleSignup).Methods("POST")
	router.HandleFunc("/upload", hub.HandleUpload).Methods("POST")
	router.HandleFunc("/upload", hub.HandleUploadOptions).Methods("OPTIONS")
	router.HandleFunc("/signup", hub.HandleSignupOtions).Methods("OPTIONS")
	router.HandleFunc("/sync", hub.HandleSyncRequest).Methods("GET")
	// router.HandleFunc("/messages/pending", hub.HandlePendingMessagesRequest).Methods("GET")
	router.HandleFunc("/sync", hub.HandleSyncRequestOptions).Methods("OPTIONS")
	// router.HandleFunc("/messages/pending", hub.HandlePendingMessagesRequestOptions).Methods("OPTIONS")
	router.HandleFunc("/login", hub.HandleLogin).Methods("POST")
	router.HandleFunc("/login", hub.HandleLoginOptions).Methods("OPTIONS")
	router.HandleFunc("/users", hub.HandleUsersRequest).Methods("GET")
	router.HandleFunc("/users", hub.HandleUsersOptionsRequest).Methods("OPTIONS")
	router.HandleFunc("/file/{id}", hub.HandleFileRequest)
	router.HandleFunc("/file/{id}", hub.HandleFileOptionsRequest)

	fmt.Println("Hello,World ! ")
	http.ListenAndServe(":8080", router)
}
