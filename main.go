package main

import "fmt"

func main() {
	idents, err := FindIdentities()
	if err != nil {
		panic(err)
	}

	for _, ident := range idents {
		defer ident.Close()

		crt, err := ident.GetCertificate()
		if err != nil {
			panic(err)
		}

		if crt.Subject.CommonName != "certstore-test" {
			continue
		}

		if err := ident.Destroy(); err != nil {
			fmt.Println(err)
		}
	}
}
