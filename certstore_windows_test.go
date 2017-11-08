package main

import (
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
}
