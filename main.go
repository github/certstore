package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
)

func main() {
	idents, err := FindIdentities()
	if err != nil {
		panic(err)
	}

	for _, ident := range idents {
		crt, err := ident.GetCertificate()
		if err != nil {
			panic(err)
		}

		if crt.Subject.CommonName != "Ben Toews" {
			continue
		}

		signer, err := ident.GetSigner()
		if err != nil {
			panic(err)
		}

		msg := []byte("hello, world!")
		digest := sha256.Sum256(msg)

		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			panic(err)
		}

		if err := crt.CheckSignature(x509.SHA256WithRSA, msg, sig); err != nil {
			panic(err)
		}
	}
}
