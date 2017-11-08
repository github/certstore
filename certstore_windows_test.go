package main

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
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

	signer, err := ident.GetSigner()
	if err != nil {
		t.Fatal(err)
	}

	// SHA1WithRSA
	msg := []byte("hello world")
	digest1 := sha1.Sum(msg)

	sig, err := signer.Sign(rand.Reader, digest1[:], crypto.SHA1)
	if err != nil {
		t.Fatal(err)
	}

	if err = crt.CheckSignature(x509.SHA1WithRSA, msg, sig); err != nil {
		t.Fatal(err)
	}

	// SHA256WithRSA
	digest256 := sha256.Sum256(msg)

	sig, err = signer.Sign(rand.Reader, digest256[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	if err = crt.CheckSignature(x509.SHA256WithRSA, msg, sig); err != nil {
		t.Fatal(err)
	}

	// SHA384WithRSA
	digest384 := sha512.Sum384(msg)

	sig, err = signer.Sign(rand.Reader, digest384[:], crypto.SHA384)
	if err != nil {
		t.Fatal(err)
	}

	if err = crt.CheckSignature(x509.SHA384WithRSA, msg, sig); err != nil {
		t.Fatal(err)
	}

	// SHA512WithRSA
	digest512 := sha512.Sum512(msg)

	sig, err = signer.Sign(rand.Reader, digest512[:], crypto.SHA512)
	if err != nil {
		t.Fatal(err)
	}

	if err = crt.CheckSignature(x509.SHA512WithRSA, msg, sig); err != nil {
		t.Fatal(err)
	}

	// Unimplemented hash algo
	digestmd5 := md5.Sum(msg)

	_, err = signer.Sign(rand.Reader, digestmd5[:], crypto.SHA512)
	if err == nil {
		t.Fatal("expected an error using md5 digest")
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
