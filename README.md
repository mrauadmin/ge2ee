# Golang End-to-end encryption Library (Proof of Concept)
---

---

### Description:
Beacuse of this being a *Proof of Concept* that still needs a lot of work to be actually useable, I will not provide the instalation guide. Instead, I will explain how it works and why it works.

### Explenation:

#### Basics:
The most basic explenation of E2EE (End-to-end encryption) is:
>End-to-end encryption is a private communication system, only communicating users can participate, no adversary nor eavesdropper can interfere, not the communication system provider, telecom providers, Internet providers, nor malicious actors, only communicating users can access the cryptographic keys needed to converse.
[By Wikipedia](https://en.wikipedia.org/wiki/End-to-end_encryption)

Basicly two people exchange a [Public Key](https://en.wikipedia.org/wiki/Public-key_cryptography) that then is used to generate a set of Private Key which actually encrypt the message. It works by utilizing Curve Cryptography and some higher brain power math that we will not get into right now.

#### Code Explenation:
To every request containing corerct headers `PK` *- device's public key*, `SIG` *- signature of both of these values, signed with device's private key* the script searches the `VAULT` (a key container) for the public key. If it exists the entire body gets decrypted and then send further. If it does not find the correct headers or they are malformed the request is send further anyway. If the request contains `KX` *- Curve25519 public key*, `PK` and `SIG` it tells the script to start the connection and also send its own *Curve25519 public key*. The current scirpt is actually a server (contains the public keys and initializes the connections) and also like a client (uses the provided keys).

While I tried using as much of buil-in packages as possible, the most important package (X25519 function) was only available with an official [curve25519](https://pkg.go.dev/golang.org/x/crypto@v0.4.0/curve25519) package from Google. Witch is not ideal but also not so bad.
