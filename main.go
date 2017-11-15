package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/pkg/errors"
)

func main() {
	fmt.Println("foo")
	// create()
	check()
	delete()
}

func check() {
	store, err := Open()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer store.Close()

	idents, err := store.Identities()
	if err != nil {
		fmt.Println(err)
		return
	}

	hash := crypto.SHA256
	digest := sha256.Sum256([]byte("hi"))

	for _, ident := range idents {
		defer ident.Close()

		if signer, err := ident.Signer(); err != nil {
			fmt.Println(err)
			continue
		} else {
			if _, err := signer.Sign(rand.Reader, digest[:], hash); err != nil {
				fmt.Println(err)
				continue
			}
		}
	}

	fmt.Println("Checked")
}

func create() {
	f, err := os.Open("./test_data/rsa.pfx")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, f); err != nil {
		fmt.Println(err)
		return
	}

	store, err := Open()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer store.Close()

	if err := store.Import(buf.Bytes(), "asdf"); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Created")
}

func delete() {
	store, err := Open()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer store.Close()

	idents, err := store.Identities()
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, ident := range idents {
		defer ident.Close()

		crt, err := ident.Certificate()
		if err != nil {
			fmt.Println(err)
			continue
		}

		if crt.Subject.CommonName != "certstore-test" {
			continue
		}

		if err := ident.Delete(); err != nil {
			fmt.Println(errors.Wrap(err, "failed to destroy identity"))
			continue
		}

		fmt.Println("Deleted")
	}
}
