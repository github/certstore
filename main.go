package main

import "fmt"

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

		if err := ident.Destroy(); err != nil {
			panic(err)
		}

		fmt.Println("Deleted")
	}
}
