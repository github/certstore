package certstore

import (
	"bytes"
	"crypto/x509"
	"io"
	"os"
	"testing"
)

type identityFixture int

const (
	iRSA identityFixture = iota
	iEC
	iCA
)

func (i identityFixture) pfx() []byte {
	var path string
	switch i {
	case iRSA:
		path = "test_data/certstore-rsa.pfx"
	case iEC:
		path = "test_data/certstore-ec.pfx"
	case iCA:
		path = "test_data/certstore-ca.pfx"
	default:
		panic("bad fixture")
	}

	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, f); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func (i identityFixture) cn() string {
	switch i {
	case iRSA:
		return "rsa"
	case iEC:
		return "ec"
	case iCA:
		return "ca"
	}

	panic("bad fixture")
}

func init() {
	// delete any fixtures from a previous test run.
	if err := clearFixtures(); err != nil {
		panic(err)
	}
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

func withIdentity(t *testing.T, i identityFixture, cb func(Identity)) {
	withStore(t, func(store Store) {
		// Import an identity
		if err := store.Import(i.pfx(), "asdf"); err != nil {
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

			if isFixture(crt) && crt.Subject.CommonName == i.cn() {
				if found != nil {
					t.Fatal("duplicate identity imported")
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

func clearFixtures() error {
	store, err := Open()
	if err != nil {
		return err
	}
	defer store.Close()

	idents, err := store.Identities()
	if err != nil {
		return err
	}
	for _, ident := range idents {
		defer ident.Close()
	}

	for _, ident := range idents {
		crt, err := ident.Certificate()
		if err != nil {
			return err
		}

		if isFixture(crt) {
			if err := ident.Delete(); err != nil {
				return err
			}
		}
	}

	return nil
}

func isFixture(crt *x509.Certificate) bool {
	return len(crt.Subject.Organization) == 1 && crt.Subject.Organization[0] == "certstore"
}
