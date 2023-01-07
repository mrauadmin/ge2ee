package cryptish

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	ed519 "crypto/ed25519"

	c519 "golang.org/x/crypto/curve25519"
)

//TODO
//Split this to multiple functions for convinience

//Twisted Edwards to Montgomery:
//https://stackoverflow.com/questions/62586488/how-do-i-sign-a-curve25519-key-in-golang

// "string" is the public key encoded in base64
// "[]byte" is the secret of a client connected to the public key
var vault = make(map[string][]byte)

var pub_key_device ed519.PublicKey
var priv_key_device ed519.PrivateKey

// https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1
func Ge2ee(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Println("starting handling...")

		if len(pub_key_device) == 0 && len(priv_key_device) == 0 {
			var err error
			pub_key_device, priv_key_device, err = ed519.GenerateKey(rand.Reader)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println("generated the keys...")
		}

		//shared public key, used for the ECDH
		kx, _ := base64.StdEncoding.DecodeString(r.Header.Get("KX"))
		//shared public key, used for verification
		pk, _ := base64.StdEncoding.DecodeString(r.Header.Get("PK"))
		//signature of bot of these values connected together
		sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("SIG"))

		//TODO
		//Send KX in header and the appropriate keys when
		//signature of a client is not present in the vault

		//Check if kx_b64, pk_b64 and sig_b64 are present
		//
		//Presence of all indicates that the sender wants to start ECDH with us
		if len(kx) != 0 && len(pk) != 0 && len(sig) != 0 {
			fmt.Println("Started ECDH...")

			//TODO
			//Make this a oneliner, maybe even wihtout defining the msg var
			msg := kx[:0]
			msg = append(msg[:], pk[:]...)

			//We verify if the message actualy comes from the actual owner
			//of the public key
			if ed519.Verify(pk, msg, sig) {
				//START ECDH

				//roll a random 32bit number and save it in memory
				//
				//a[31]

				randb32 := make([]byte, 32)
				_, err := rand.Read(randb32)
				if err != nil {
					fmt.Println(err)
				}

				//generate a shared secret from provided data
				//
				//secret = c519.X25519(a, K_A)

				secret, err := c519.X25519(randb32, kx)
				if err != nil {
					fmt.Println(err)
				}
				fmt.Println(string(secret))

				//TODO
				//add security checks, like checking if provided public key is on the curve
				//and if it is all zeros etc.

				//generate public key off a X25519 curve
				//
				//K_A = X25519(a, 9)

				//var Basepoint is the "9"

				K_A, err := c519.X25519(randb32, c519.Basepoint)
				if err != nil {
					fmt.Println(err)
				}

				//add valus to the vault
				vault[r.Header.Get("PK")] = secret
				//send the response

				w.Header().Add("KX", base64.StdEncoding.EncodeToString(K_A))
				w.Header().Add("PK", base64.StdEncoding.EncodeToString(pub_key_device))
				w.Header().Add("SIG", base64.StdEncoding.EncodeToString(ed519.Sign(priv_key_device, pub_key_device)))

				fmt.Println("Completed ECDH...")

				h.ServeHTTP(w, r)
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}

			//Presence only of the "pk" and "sig" means that the message has been encrypted before
		} else if len(kx) == 0 && len(pk) != 0 && len(sig) != 0 {
			fmt.Println("Post ECDH")

			var body []byte
			r.Body.Read(body)
			msg := pk[:0]
			msg = append(msg[:], body[:]...)

			if ed519.Verify(pk, msg, sig) {
				fmt.Println("Checked the signature, it cool")
				if secret, found := vault[r.Header.Get("PK")]; found {
					//TODO
					//get MSG from body, body of the request is the encyrpted msg
					//this is just a placeholder for testing
					b, _ := base64.StdEncoding.DecodeString(r.Header.Get("MSG"))
					fmt.Println(string(DecryptAES(secret, b)))
				} else {
					w.WriteHeader(http.StatusBadRequest)
				}
			}
			w.WriteHeader(http.StatusBadRequest)
		}

		h.ServeHTTP(w, r)
		w.Write([]byte("run after, "))
	}
	return http.HandlerFunc(fn)
}

func DecryptAES(key []byte, ct []byte) []byte {
	c, _ := aes.NewCipher(key)

	pt := make([]byte, len(ct))
	c.Decrypt(pt, ct)

	return pt
}
