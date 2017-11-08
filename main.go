package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
)

func main() {
	idents, err := FindIdentities()
	if err != nil {
		panic(err)
	}

	for _, ident := range idents {
		_, err := ident.GetCertificate()
		if err != nil {
			panic(err)
		}

		signer, err := ident.GetSigner()
		if err != nil {
			panic(err)
		}

		msg := []byte("hello, world!")
		digest := sha256.Sum256(msg)

		if _, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
			panic(err)
		}
	}
}
