package ge2ee

import (
	"bytes"
	"crypto/aes"
	ed519 "crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	c519 "golang.org/x/crypto/curve25519"
)

type loot struct {
	time   int64
	secret []byte
}

var vault = make(map[string]loot)

var pub_key_device ed519.PublicKey
var priv_key_device ed519.PrivateKey
var err error

func Ge2eeClient(request *http.Request) {

	if len(pub_key_device) == 0 && len(priv_key_device) == 0 {

		//TODO
		//implement settings declaration

		pub_key_device, priv_key_device, err = ed519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Println(err)
		}
	}
	e2ee(request, &http.Client{})

}

func e2ee(request *http.Request, client *http.Client) *http.Response {
	req, _ := http.NewRequest("GET", request.URL.Scheme, nil)

	//TODO
	//parse the url

	//TODO
	//error handling

	//roll a random 32bit number and save it in memory
	//
	//a[31]

	randb32 := make([]byte, 32)
	_, err := rand.Read(randb32)
	if err != nil {
		fmt.Println(err)
	}

	//generate public key off a X25519 curve
	//
	//KX = X25519(a, 9)
	//var Basepoint is the "9" stated in RFC7748

	KX, err := c519.X25519(randb32, c519.Basepoint)
	if err != nil {
		fmt.Println(err)
	}

	//TODO
	//add security checks, like checking if provided public key is on the curve
	//and if it is all zeros etc.

	req.Header.Set("KX", base64.StdEncoding.EncodeToString(KX))
	req.Header.Set("PK", base64.StdEncoding.EncodeToString(pub_key_device))
	req.Header.Set("SIG", base64.StdEncoding.EncodeToString(ed519.Sign(priv_key_device, appendnhash(pub_key_device, KX))))

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	defer resp.Body.Close()
	ka, _ := base64.StdEncoding.DecodeString(resp.Header.Values("KX")[0])
	pk := resp.Header.Values("PK")[0]

	secret, err := c519.X25519(randb32, ka)
	if err != nil {
		fmt.Println(err)
	}

	//add values to the vault
	if entry, ok := vault[pk]; ok {

		// Then we modify the copy
		entry.secret = secret
		entry.time = time.Now().Unix()

		// Then we reassign map entry
		vault[pk] = entry
	}
	a, err := io.ReadAll(request.Body)
	if err != nil {
		fmt.Println(err)
	}
	b, _ := encryptAES(secret, a)

	req_exit, _ := http.NewRequest(request.Method, request.URL.Scheme, bytes.NewReader(b))
	req_exit.Header.Set("PK", base64.StdEncoding.EncodeToString(pub_key_device))
	req_exit.Header.Set("SIG", base64.StdEncoding.EncodeToString(ed519.Sign(priv_key_device, appendnhash(pub_key_device, b))))

	resp2, err := client.Do(req_exit)
	if err != nil {
		fmt.Println(err)
	}
	return resp2
}

func encryptAES(key []byte, ct []byte) ([]byte, error) {
	if len(ct) == 0 {
		return nil, errors.New("body is empty, encryption failed")
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
	ctBytes := []byte(ct)
	blockSize := c.BlockSize()
	padding := blockSize - (len(ctBytes) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	ctBytes = append(ctBytes, padtext...)

	buff := make([]byte, blockSize)
	var out []byte
	for i := 0; i < (len(ctBytes) / blockSize); i++ {
		c.Encrypt(buff, ctBytes[i*blockSize:])
		out = append(out, buff...)
	}
	return out, nil
}

// Concatenate the public key (pk) and message (msg). Returns a sha256 hash (in []byte) of this concatenation.
func appendnhash(pk []byte, msg []byte) []byte {
	p := pk[:]
	p = append(p[:], msg[:]...)
	s2 := sha256.New()
	s2.Write(p)
	return s2.Sum(nil)
}
