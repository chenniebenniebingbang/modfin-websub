package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
)

// Use hash map w/o mutex since the requirements does not specify handling concurrency
var Subscribers = make(map[string][][]string)

var client = &http.Client{}

func main() {
	http.HandleFunc("/", handlePost)

	http.HandleFunc("/publisher", handlePublish)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

type subPost struct {
	Callback string `json:"hub.callback"`
	Mode     string `json:"hub.mode"`
	Topic    string `json:"hub.topic"`
	Secret   string `json:"hub.secret"`
}

type publishPost struct {
	Message string `json:"message"`
	Topic   string `json:"topic"`
}

// Can be sent using:
// curl -X POST "http://localhost:8080/publisher?topic=/a/topic&message=hej"
func handlePublish(w http.ResponseWriter, r *http.Request) {
	var message publishPost

	err := r.ParseForm()
	defer r.Body.Close()

	if err != nil {
		log.Println("Error reading request from Publisher")
		return
	}

	message.Topic = r.FormValue("topic")
	message.Message = r.FormValue("message")

	sendMessageToSubs(message)
}

func handlePost(w http.ResponseWriter, r *http.Request) {
	var message subPost

	err := r.ParseForm()
	defer r.Body.Close()

	if err != nil {
		log.Println("Error reading Subscription request")
		return
	}

	message.Callback = r.FormValue("hub.callback")
	message.Mode = r.FormValue("hub.mode")
	message.Topic = r.FormValue("hub.topic")
	message.Secret = r.FormValue("hub.secret")

	if r.Method == "POST" {
		if status := verifySub(message.Mode, message.Topic, message.Callback) && message.Callback != ""; status == true {
			Subscribers[message.Topic] = append(Subscribers[message.Topic], []string{message.Callback, message.Secret})
		}
	}
}

func sendMessageToSubs(post publishPost) {
	for _, sub := range Subscribers[post.Topic] {
		sendTopicContent(post, sub[0], sub[1])
	}
}

func sendTopicContent(post publishPost, callback string, secret string) {
	jsonData, _ := json.Marshal(post)

	req, _ := http.NewRequest("POST", callback, bytes.NewBuffer(jsonData))

	if secret == "" {
		resp, _ := client.Do(req)
		defer resp.Body.Close()

	} else {
		signature := "sha256=" + HMACSigning(secret, jsonData)

		req.Header.Set("X-Hub-Signature", signature)

		resp, _ := client.Do(req)

		defer resp.Body.Close()

	}
}

func verifySub(mode string, topic string, callback string) bool {
	randString := generateChallenge(10)

	req, _ := http.NewRequest("GET", callback, nil)

	q := req.URL.Query()
	q.Add("hub.mode", mode)
	q.Add("hub.topic", topic)
	q.Add("hub.challenge", randString)
	req.URL.RawQuery = q.Encode()

	resp, _ := client.Do(req)

	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	answer := string(bodyBytes)

	if answer != randString {
		return false
	}

	return true
}

func HMACSigning(secret string, body []byte) string {
	//	From W3C:
	//	The signature MUST be computed using the HMAC algorithm [RFC6151]
	//	with the request body as the data and the hub.secret as the key.
	h := hmac.New(sha256.New, []byte(secret))

	h.Write(body)

	return hex.EncodeToString(h.Sum(nil))
}

// Make the random string to verify subscriber
func generateChallenge(length int) string {
	result := make([]byte, length)

	for i := 0; i < length; i++ {
		result[i] = byte(rand.IntN(126-33+1) + 33)
	}

	return string(result)
}
