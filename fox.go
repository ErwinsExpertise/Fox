package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/gorilla/mux"
)

type GHLoad struct {
	Ref        string `json:"ref, omitempty"`
	Repository Repo   `json:"repository, omitempty"`
	Pusher     Push   `json:"pusher, omitempty"`
}

type Repo struct {
	ID        int    `json:"id, omitempty"`
	Node_ID   string `json:"node_id, omitempty"`
	Name      string `json:"name, omitempty"`
	URL       string `json:"html_url, omitempty"`
	UpdatedAt string `json:"updated_at, omitempty"`
}

type Push struct {
	Name  string `json:"name, omitempty"`
	Email string `json:"email, omitempty"`
}

var (
	secret string
	resp   GHLoad
)

func init() {
	secret = os.Getenv("GHTOKEN")
	if _, err := os.Stat("/var/log/fox"); os.IsNotExist(err) {
		err := os.Mkdir("/var/log/fox", 0755)
		if err != nil {
			log.Panic(err)
		}
	}

	logFile, err := os.OpenFile("/var/log/fox/fox.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		log.Panic(err)
	}
	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)
}

func main() {
	rout := mux.NewRouter()
	rout.HandleFunc("/updaterepo", UpdateHandler).Methods("POST")
	rout.HandleFunc("/activity", ActivityHandler).Methods("GET")

	log.Println("Now listening on :1337")
	log.Println(http.ListenAndServe(":1337", rout))
}

func UpdateHandler(w http.ResponseWriter, r *http.Request) {
	valid, payload, err := ValidateRequest(r, []byte(secret))
	if valid != true {
		log.Printf("%v\n", err)
		log.Println("Unauthorized attempt from " + r.RemoteAddr)
		http.Error(w, "Unauthorized Access", http.StatusUnauthorized)
		return
	}

	json.Unmarshal(payload, &resp)
	log.Printf("Recieved push event.\nRef: %v\nID: %v\nNode_ID: %v\nName: %v\nRepo URL: %v\nUpdated At: %v\nPusher: %v\nEmail: %v\n",
		resp.Ref,
		resp.Repository.ID,
		resp.Repository.Node_ID,
		resp.Repository.Name,
		resp.Repository.URL,
		resp.Repository.UpdatedAt,
		resp.Pusher.Name,
		resp.Pusher.Email)

	UpdateRepo(resp.Repository.Name)
}

func ActivityHandler(w http.ResponseWriter, r *http.Request) {
	fil, err := os.Open("/var/log/fox/fox.log")
	if err != nil {
		log.Println(err)
	}

	defer fil.Close()

	output, err := ioutil.ReadAll(fil)
	if err != nil {
		log.Println(err)
	}

	w.Write(output)
}

func UpdateRepo(project string) {
	os.Setenv("GHPROJECT", project)
	cmd := exec.Command("./update.sh")

	err := cmd.Run()
	if err != nil {
		log.Println("Failed to update project " + project)
	}
}

// genMAC generates the HMAC signature for a message provided the secret key
// and hashFunc.
func genMAC(message, key []byte, hashFunc func() hash.Hash) []byte {
	mac := hmac.New(hashFunc, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// checkMAC reports whether messageMAC is a valid HMAC tag for message.
func checkMAC(message, messageMAC, key []byte, hashFunc func() hash.Hash) bool {
	expectedMAC := genMAC(message, key, hashFunc)
	return hmac.Equal(messageMAC, expectedMAC)
}

func ValidateRequest(r *http.Request, secretToken []byte) (bool, []byte, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
	}
	payload := body

	if len(secretToken) > 0 {
		sig := r.Header.Get("X-Hub-Signature")
		messageMAC, err := hex.DecodeString(sig[5:])
		if err != nil {
			log.Println(err)
		}

		if !checkMAC(payload, messageMAC, secretToken, sha1.New) {
			return false, nil, errors.New("payload signature check failed")
		}
	}
	return true, payload, nil

}
