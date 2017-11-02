package main

import (
	"fmt"
	"os"
)

func main() {
	idents := findIdentities()

	for i, ident := range idents {
		defer ident.Close()

		f, err := os.Create(fmt.Sprintf("%d.der", i))
		if err != nil {
			panic(err)
		}

		if _, err := f.Write(ident.getCertificate().getDER()); err != nil {
			panic(err)
		}
	}
}
