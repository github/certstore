package main

import (
	"fmt"
)

func main() {
	idents, err := FindIdentities()
	if err != nil {
		panic(err)
	}

	for _, ident := range idents {
		cert, err := ident.GetCertificate()
		if err != nil {
			panic(err)
		}

		fmt.Printf("CN=%s\n", cert.Subject.CommonName)

		if _, err = ident.GetPrivateKey(); err != nil {
			panic(err)
		}
	}
}
