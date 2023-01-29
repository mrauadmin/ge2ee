package ge2ee

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	ed519 "crypto/ed25519"

	c519 "golang.org/x/crypto/curve25519"
)

//Twisted Edwards to Montgomery:
//https://stackoverflow.com/questions/62586488/how-do-i-sign-a-curve25519-key-in-golang
//https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1

//TODO
//flush vault of old secrets

// "string" is the public key encoded in base64,
// "[]byte" is the secret of a client connected to the public key

type settings struct {
	flushtime int64
	maxconn   int
}

type loot struct {
	time   int64
	secret []byte
}

var vault = make(map[string]loot)

var pub_key_device ed519.PublicKey
var priv_key_device ed519.PrivateKey
var err error

// Ge2ee takes one argument, a http.Handler and returns a http.Handler.
// It handles the authentication, encryption and decryption of every request.
func Ge2ee(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if len(pub_key_device) == 0 && len(priv_key_device) == 0 {

			//TODO
			//implement settings declaration

			pub_key_device, priv_key_device, err = ed519.GenerateKey(rand.Reader)
			if err != nil {
				fmt.Println(err)
			}
		}

		//shared public key, used for the ECDH
		kx, _ := base64.StdEncoding.DecodeString(r.Header.Get("KX"))
		//shared public key, used for verification
		pk, _ := base64.StdEncoding.DecodeString(r.Header.Get("PK"))
		//signature of both of these values connected together
		sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("SIG"))

		//Check if kx_b64, pk_b64 and sig_b64 are present
		//Presence of all, indicates that the sender wants to start ECDH with us
		if len(kx) != 0 && len(pk) != 0 && len(sig) != 0 {
			//We verify if the message actualy comes from the actual owner
			//of the public key
			if ed519.Verify(pk, appendnhash(pk, kx), sig) {
				e2ee(w, r, kx)
				h.ServeHTTP(w, r)

				//the passed handler gets executed here
				//after that we need to encrypt the body etc.

			} else {
				w.WriteHeader(http.StatusBadRequest)
			}

			//Presence only of the "pk" and "sig" means that the message has been encrypted before
		} else if len(kx) == 0 && len(pk) != 0 && len(sig) != 0 {
			c, err := io.ReadAll(r.Body)
			if err != nil {
				fmt.Println(err)
			}
			var a []byte
			a, _ = base64.StdEncoding.DecodeString(string(c))

			if ed519.Verify(pk, appendnhash(pk, a), sig) {
				if entry, found := vault[r.Header.Get("PK")]; found {
					//TODO
					//replace 5000 with settings.flushtime
					if entry.time <= time.Now().Unix()-5000 {
						w.WriteHeader(http.StatusGatewayTimeout)
					}
					decmsg, err := decryptAES(entry.secret, a)
					if err != nil {
						w.WriteHeader(http.StatusBadRequest)
					}
					r.Body = io.NopCloser(bytes.NewReader(decmsg))
					h.ServeHTTP(w, r)
				} else {
					w.WriteHeader(http.StatusBadRequest)
				}
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
		}
	}
}

// Encrypt the body AFTER executing the handler.
func EncryptBody(w http.ResponseWriter, r *http.Request, ct []byte) ([]byte, error) {
	if secret, found := vault[r.Header.Get("PK")]; found {
		encmsg, err := encryptAES(secret.secret, ct)
		if err != nil {
			return nil, errors.New("body is empty, encryption failed")
		}
		w.Header().Add("PK", base64.StdEncoding.EncodeToString(pub_key_device))
		w.Header().Add("SIG", base64.StdEncoding.EncodeToString(ed519.Sign(priv_key_device, appendnhash(pub_key_device, encmsg))))
		return encmsg, nil
	}

	return nil, errors.New("PK not")
}

// e2ee generates the secret based of of the data from the request and inserts into the vault.
func e2ee(w http.ResponseWriter, r *http.Request, kx []byte) {
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

	//generate a shared secret from provided data
	//
	//secret = c519.X25519(a, KX)

	secret, err := c519.X25519(randb32, kx)
	if err != nil {
		fmt.Println(err)
	}

	//TODO
	//add security checks, like checking if provided public key is on the curve
	//and if it is all zeros etc.

	//add values to the vault
	if entry, ok := vault[r.Header.Get("PK")]; ok {

		// Then we modify the copy
		entry.secret = secret
		entry.time = time.Now().Unix()

		// Then we reassign map entry
		vault[r.Header.Get("PK")] = entry
	}

	//send the response
	w.Header().Add("KX", base64.StdEncoding.EncodeToString(KX))
	w.Header().Add("PK", base64.StdEncoding.EncodeToString(pub_key_device))
	w.Header().Add("SIG", base64.StdEncoding.EncodeToString(ed519.Sign(priv_key_device, appendnhash(pub_key_device, KX))))
}

// Decrypt []byte with provided key using AES decryption.
// decryptAES splits the provided encrypted byte array into blocks with the length of the key
// and then decrypts the blocks with the provided key.
func decryptAES(key []byte, ct []byte) ([]byte, error) {
	if len(ct) == 0 {
		return nil, errors.New("body is empty, decryption failed")
	}
	c, _ := aes.NewCipher(key)
	blockSize := c.BlockSize()

	buff := make([]byte, blockSize)
	var out []byte
	for i := 0; i < (len(ct) / blockSize); i++ {
		c.Decrypt(buff, ct[i*blockSize:])
		out = append(out, buff...)
	}

	padLen := int(out[len(ct)-1])
	return out[:len(out)-padLen], nil
}

// Encrypt []byte with provided key using AES enryption.
// encryptAES splits the provided byte array into blocks with the length of the key
// and then encrypts the blocks with the provided key.
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

// Concatenate the public key (pk) and message (msg).
// Returns a sha256 hash (in []byte) of this concatenation.
func appendnhash(pk []byte, msg []byte) []byte {
	p := pk[:]
	p = append(p[:], msg[:]...)
	s2 := sha256.New()
	s2.Write(p)
	return s2.Sum(nil)
}
