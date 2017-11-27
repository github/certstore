package certstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"testing"

	"golang.org/x/crypto/pkcs12"
)

func TestImportDeleteRSA(t *testing.T) {
	ImportDeleteHelper(t, rsaPFX, "asdf")
}

func TestImportDeleteECDSA(t *testing.T) {
	ImportDeleteHelper(t, ecPFX, "asdf")
}

// ImportDeleteHelper is an abstraction for testing identity Import()/Delete().
func ImportDeleteHelper(t *testing.T, pfx []byte, password string) {
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
			crt, errr := ident.Certificate()
			if errr != nil {
				t.Fatal(errr)
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

		// Delete it
		if err = found.Delete(); err != nil {
			t.Fatal(err)
		}

		// Look for our deleted identity
		idents, err = store.Identities()
		if err != nil {
			t.Fatal(err)
		}
		for _, ident := range idents {
			defer ident.Close()
		}

		found = nil
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
		if found != nil {
			t.Fatal("imported identity not deleted")
		}
	})
}

func TestSignerRSA(t *testing.T) {
	priv, crt, err := pkcs12.Decode(rsaPFX, "asdf")
	if err != nil {
		t.Fatal(err)
	}

	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("expected priv to be an RSA private key")
	}

	withIdentity(t, rsaPFX, "asdf", func(ident Identity) {
		signer, err := ident.Signer()
		if err != nil {
			t.Fatal(err)
		}

		pk := signer.Public()
		rsaPub, ok := pk.(*rsa.PublicKey)
		if !ok {
			t.Fatal("expected pk to be an RSA public key")
		}

		if rsaPub.E != rsaPriv.E {
			t.Fatalf("bad E. Got %d, expected %d", rsaPub.E, rsaPriv.E)
		}

		if rsaPub.N.Cmp(rsaPriv.N) != 0 {
			t.Fatalf("bad N. Got %s, expected %s", rsaPub.N.Text(16), rsaPriv.N.Text(16))
		}

		// SHA1WithRSA
		sha1Digest := sha1.Sum([]byte("hello"))
		sig, err := signer.Sign(rand.Reader, sha1Digest[:], crypto.SHA1)
		if err != nil {
			// SHA1 should be supported by all platforms.
			t.Fatal(err)
		}
		if err = crt.CheckSignature(x509.SHA1WithRSA, []byte("hello"), sig); err != nil {
			t.Fatal(err)
		}

		// SHA256WithRSA
		sha256Digest := sha256.Sum256([]byte("hello"))
		sig, err = signer.Sign(rand.Reader, sha256Digest[:], crypto.SHA256)
		if err == ErrUnsupportedHash {
			// Some Windows CSPs may not support this algorithm. Pass...
		} else if err != nil {
			t.Fatal(err)
		} else {
			if err = crt.CheckSignature(x509.SHA256WithRSA, []byte("hello"), sig); err != nil {
				t.Fatal(err)
			}
		}

		// SHA384WithRSA
		sha384Digest := sha512.Sum384([]byte("hello"))
		sig, err = signer.Sign(rand.Reader, sha384Digest[:], crypto.SHA384)
		if err == ErrUnsupportedHash {
			// Some Windows CSPs may not support this algorithm. Pass...
		} else if err != nil {
			t.Fatal(err)
		} else {
			if err = crt.CheckSignature(x509.SHA384WithRSA, []byte("hello"), sig); err != nil {
				t.Fatal(err)
			}
		}

		// SHA512WithRSA
		sha512Digest := sha512.Sum512([]byte("hello"))
		sig, err = signer.Sign(rand.Reader, sha512Digest[:], crypto.SHA512)
		if err == ErrUnsupportedHash {
			// Some Windows CSPs may not support this algorithm. Pass...
		} else if err != nil {
			t.Fatal(err)
		} else {
			if err = crt.CheckSignature(x509.SHA512WithRSA, []byte("hello"), sig); err != nil {
				t.Fatal(err)
			}
		}

		// Bad digest size
		_, err = signer.Sign(rand.Reader, sha1Digest[5:], crypto.SHA1)
		if err == nil {
			t.Fatal("expected error for bad digest size")
		}

		// Unsupported hash
		sha224Digest := sha256.Sum224([]byte("hello"))
		_, err = signer.Sign(rand.Reader, sha224Digest[:], crypto.SHA224)
		if err != ErrUnsupportedHash {
			t.Fatal("expected ErrUnsupportedHash, got ", err)
		}
	})
}

func TestSignerECDSA(t *testing.T) {
	priv, crt, err := pkcs12.Decode(ecPFX, "asdf")
	if err != nil {
		t.Fatal(err)
	}

	ecPriv, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("expected priv to be an ECDSA private key")
	}

	withIdentity(t, ecPFX, "asdf", func(ident Identity) {
		signer, err := ident.Signer()
		if err != nil {
			t.Fatal(err)
		}

		pk := signer.Public()
		ecPub, ok := pk.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("expected pk to be an RSA public key")
		}

		if ecPub.X.Cmp(ecPriv.X) != 0 {
			t.Fatalf("bad X. Got %s, expected %s", ecPub.X.Text(16), ecPriv.X.Text(16))
		}

		if ecPub.Y.Cmp(ecPriv.Y) != 0 {
			t.Fatalf("bad Y. Got %s, expected %s", ecPub.Y.Text(16), ecPriv.Y.Text(16))
		}

		// ECDSAWithSHA1
		sha1Digest := sha1.Sum([]byte("hello"))
		sig, err := signer.Sign(rand.Reader, sha1Digest[:], crypto.SHA1)
		if err != nil {
			t.Fatal(err)
		}
		if err = crt.CheckSignature(x509.ECDSAWithSHA1, []byte("hello"), sig); err != nil {
			t.Fatal(err)
		}

		// ECDSAWithSHA256
		sha256Digest := sha256.Sum256([]byte("hello"))
		sig, err = signer.Sign(rand.Reader, sha256Digest[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if err = crt.CheckSignature(x509.ECDSAWithSHA256, []byte("hello"), sig); err != nil {
			t.Fatal(err)
		}

		// ECDSAWithSHA384
		sha384Digest := sha512.Sum384([]byte("hello"))
		sig, err = signer.Sign(rand.Reader, sha384Digest[:], crypto.SHA384)
		if err != nil {
			t.Fatal(err)
		}
		if err = crt.CheckSignature(x509.ECDSAWithSHA384, []byte("hello"), sig); err != nil {
			t.Fatal(err)
		}

		// ECDSAWithSHA512
		sha512Digest := sha512.Sum512([]byte("hello"))
		sig, err = signer.Sign(rand.Reader, sha512Digest[:], crypto.SHA512)
		if err != nil {
			t.Fatal(err)
		}
		if err = crt.CheckSignature(x509.ECDSAWithSHA512, []byte("hello"), sig); err != nil {
			t.Fatal(err)
		}

		// Bad digest size
		_, err = signer.Sign(rand.Reader, sha512Digest[5:], crypto.SHA512)
		if err == nil {
			t.Fatal("expected error for bad digest size")
		}
	})
}

func TestCertificateRSA(t *testing.T) {
	_, crtExpected, err := pkcs12.Decode(rsaPFX, "asdf")
	if err != nil {
		t.Fatal(err)
	}

	withIdentity(t, rsaPFX, "asdf", func(ident Identity) {
		crtActual, err := ident.Certificate()
		if err != nil {
			t.Fatal(err)
		}
		if !crtActual.Equal(crtExpected) {
			t.Fatal("Expected cert to match pfx")
		}

		chain, err := ident.CertificateChain()
		if err != nil {
			t.Fatal(err)
		}
		if len(chain) < 1 {
			t.Fatal("empty chain")
		}
		if !crtActual.Equal(chain[0]) {
			t.Fatal("first chain cert should be leaf")
		}
	})
}

func TestCertificateEC(t *testing.T) {
	_, crtExpected, err := pkcs12.Decode(ecPFX, "asdf")
	if err != nil {
		t.Fatal(err)
	}

	withIdentity(t, ecPFX, "asdf", func(ident Identity) {
		crtActual, err := ident.Certificate()
		if err != nil {
			t.Fatal(err)
		}
		if !crtActual.Equal(crtExpected) {
			t.Fatal("Expected cert to match pfx")
		}

		chain, err := ident.CertificateChain()
		if err != nil {
			t.Fatal(err)
		}
		if len(chain) < 1 {
			t.Fatal("empty chain")
		}
		if !crtActual.Equal(chain[0]) {
			t.Fatal("first chain cert should be leaf")
		}
	})
}
