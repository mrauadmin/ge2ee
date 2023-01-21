package cryptish

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

	ed519 "crypto/ed25519"

	c519 "golang.org/x/crypto/curve25519"
)

//TODO
//Split this to multiple functions for convinience

//Twisted Edwards to Montgomery:
//https://stackoverflow.com/questions/62586488/how-do-i-sign-a-curve25519-key-in-golang
//https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1

//TODO
//flush vault of old secrets

//TODO
//encryption of outgoing messages

// "string" is the public key encoded in base64,
// "[]byte" is the secret of a client connected to the public key
var vault = make(map[string][]byte)

var pub_key_device ed519.PublicKey
var priv_key_device ed519.PrivateKey

// Ge2ee takes one argument, a http.Handler and returns a http.Handler.
// It handles the authentication, encryption and decryption of every request.
func Ge2ee(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if len(pub_key_device) == 0 && len(priv_key_device) == 0 {
			var err error
			pub_key_device, priv_key_device, err = ed519.GenerateKey(rand.Reader)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println("Generated keys")
		}

		//shared public key, used for the ECDH
		kx, _ := base64.StdEncoding.DecodeString(r.Header.Get("KX"))
		//shared public key, used for verification
		pk, _ := base64.StdEncoding.DecodeString(r.Header.Get("PK"))
		//signature of both of these values connected together
		sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("SIG"))

		//TODO
		//Send KX in header and the appropriate keys when
		//signature of a client is not present in the vault

		//Check if kx_b64, pk_b64 and sig_b64 are present
		//
		//Presence of all, indicates that the sender wants to start ECDH with us
		if len(kx) != 0 && len(pk) != 0 && len(sig) != 0 {
			//We verify if the message actualy comes from the actual owner
			//of the public key
			if ed519.Verify(pk, appendnhash(pk, kx), sig) {
				e2ee(w, r, kx)
				fmt.Println("shared keys")
				h.ServeHTTP(w, r)
				fmt.Println("run after, ")
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
				if secret, found := vault[r.Header.Get("PK")]; found {
					decmsg, err := decryptAES(secret, a)
					if err != nil {
						w.WriteHeader(http.StatusBadRequest)
					}
					r.Body = io.NopCloser(bytes.NewReader(decmsg))
					fmt.Println(string(decmsg))
					h.ServeHTTP(w, r)
					fmt.Println("run after, ")
				} else {
					w.WriteHeader(http.StatusBadRequest)
				}
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
		}
	}
}

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
	vault[r.Header.Get("PK")] = secret

	//send the response
	w.Header().Add("KX", base64.StdEncoding.EncodeToString(KX))
	w.Header().Add("PK", base64.StdEncoding.EncodeToString(pub_key_device))
	w.Header().Add("SIG", base64.StdEncoding.EncodeToString(ed519.Sign(priv_key_device, appendnhash(pub_key_device, KX))))
}

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

func encryptAES(key []byte, plaintext string) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	plaintextBytes := []byte(plaintext)
	blockSize := c.BlockSize()
	padding := blockSize - (len(plaintextBytes) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	plaintextBytes = append(plaintextBytes, padtext...)

	out := make([]byte, len(plaintext))
	c.Encrypt(out, plaintextBytes)
	return out
}

// Concatenate the public key (pk) and message (msg). Returns a sha256 hash (in []byte) of this concatenation.
func appendnhash(pk []byte, msg []byte) []byte {
	p := pk[:]
	p = append(p[:], msg[:]...)
	s2 := sha256.New()
	s2.Write(p)
	return s2.Sum(nil)
}
