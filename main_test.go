package certstore

import (
	"bytes"
	"io"
	"os"
	"testing"
)

var rsaPFX, ecPFX []byte

func init() {
	// delete any fixtures from a previous test run.
	clearFixtures()

	loadRSAPFX()
	loadECPFX()
}

func withStore(t *testing.T, cb func(Store)) {
	t.Helper()

	store, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cb(store)
}

func withIdentity(t *testing.T, pfx []byte, password string, cb func(Identity)) {
	t.Helper()

	withStore(t, func(store Store) {
		// Import an identity
		if err := store.Import(pfx, password); err != nil {
			t.Fatal(err)
		}

		// Look for our imported identity
		idents, err := store.Identities()
		if err != nil {
			t.Fatal(err)
		}
		for _, ident := range idents {
			defer ident.Close()
		}

		var found Identity
		for _, ident := range idents {
			crt, err := ident.Certificate()
			if err != nil {
				t.Fatal(err)
			}

			if crt.Subject.CommonName == "certstore-test" {
				if found != nil {
					t.Fatal("duplicate certstore-test identity imported")
				}
				found = ident
			}
		}
		if found == nil {
			t.Fatal("imported identity not found")
		}

		// Clean up after ourselves.
		defer func(f Identity) {
			if err := f.Delete(); err != nil {
				t.Fatal(err)
			}
		}(found)

		cb(found)
	})
}

func clearFixtures() {
	store, err := Open()
	if err != nil {
		panic(err)
	}
	defer store.Close()

	idents, err := store.Identities()
	if err != nil {
		panic(err)
	}
	for _, ident := range idents {
		defer ident.Close()
	}

	for _, ident := range idents {
		crt, err := ident.Certificate()
		if err != nil {
			panic(err)
		}

		if crt.Subject.CommonName == "certstore-test" {
			if err := ident.Delete(); err != nil {
				panic(err)
			}
		}
	}
}

func loadRSAPFX() {
	f, err := os.Open("test_data/rsa.pfx")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, f); err != nil {
		panic(err)
	}

	rsaPFX = buf.Bytes()
}

func loadECPFX() {
	f, err := os.Open("test_data/ec.pfx")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, f); err != nil {
		panic(err)
	}

	ecPFX = buf.Bytes()
}
