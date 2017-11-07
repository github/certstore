package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"
)

func TestWindowsRSA(t *testing.T) {
	store, err := importCertStore(rsaPFX, "asdf")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	idents, err := findIdentities(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, ident := range idents {
		defer ident.Close()
	}

	if len(idents) != 1 {
		t.Fatalf("expected 1 identity. got %d", len(idents))
	}

	ident := idents[0]

	crt, err := ident.GetCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if crt.Subject.CommonName != "Ben Toews" {
		t.Fatalf("expected CN='Ben Toews'. Got CN='%s'", crt.Subject.CommonName)
	}

	key, err := ident.GetPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	rkey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("expected rsa key")
	}

	rkey2, ok := crt.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected rsa key in cert")
	}

	if rkey.E != rkey2.E {
		t.Fatal("E doesn't match")
	}

	if rkey.N.Cmp(rkey2.N) != 0 {
		t.Fatal("N doesn't match")
	}
}

func TestWindowsEC(t *testing.T) {
	store, err := importCertStore(ecPFX, "asdf")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	idents, err := findIdentities(store)
	if err != nil {
		t.Fatal(err)
	}
	for _, ident := range idents {
		defer ident.Close()
	}

	if len(idents) != 1 {
		t.Fatalf("expected 1 identity. got %d", len(idents))
	}

	ident := idents[0]

	crt, err := ident.GetCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if crt.Subject.CommonName != "Ben Toews" {
		t.Fatalf("expected CN='Ben Toews'. Got CN='%s'", crt.Subject.CommonName)
	}

	key, err := ident.GetPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	ekey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("expected ec key")
	}

	ekey2, ok := crt.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("expected rsa key in cert")
	}

	if ekey.X.Cmp(ekey2.X) != 0 {
		t.Fatal("X doesn't match")
	}

	if ekey.Y.Cmp(ekey2.Y) != 0 {
		t.Fatal("X doesn't match")
	}
}
