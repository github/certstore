package main

/*
#cgo windows LDFLAGS: -lcrypt32 -lpthread -lncrypt -lbcrypt
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <winerror.h>
#include <stdio.h>

char* errMsg(DWORD code) {
	char* lpMsgBuf;
	DWORD ret = 0;

	ret = FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			code,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR) &lpMsgBuf,
			0, NULL);

	if (ret == 0) {
		return NULL;
	} else {
		return lpMsgBuf;
	}
}
*/
import "C"

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"
	"unsafe"
)

const (
	winTrue  C.WINBOOL = 1
	winFalse C.WINBOOL = 0
)

// winIdentity implements the Identity iterface.
type winIdentity struct {
	ctx    C.PCCERT_CONTEXT
	closed bool
}

// FindIdentities returns a slice of available signing identities.
func FindIdentities() ([]Identity, error) {
	store, err := openMyCertStore()
	if err != nil {
		return nil, err
	}
	defer store.Close()

	return findIdentities(store)
}

func findIdentities(store *winStore) ([]Identity, error) {
	idents := make([]Identity, 0)

	for ctx := store.nextCert(); ctx != nil; ctx = store.nextCert() {
		idents = append(idents, newWinIdentity(ctx))
	}

	if err := store.getError(); err != nil {
		for _, ident := range idents {
			ident.Close()
		}

		return nil, err
	}

	return idents, nil
}

func newWinIdentity(ctx C.PCCERT_CONTEXT) *winIdentity {
	return &winIdentity{ctx: C.CertDuplicateCertificateContext(ctx)}
}

// GetCertificate implements the Identity iterface.
func (i *winIdentity) GetCertificate() (*x509.Certificate, error) {
	if err := i._check(); err != nil {
		return nil, err
	}

	der := C.GoBytes(unsafe.Pointer(i.ctx.pbCertEncoded), C.int(i.ctx.cbCertEncoded))

	return x509.ParseCertificate(der)
}

// PublicKey implements the crypto.Signer interface.
func (i *winIdentity) PublicKey() crypto.PublicKey {
	cert, err := i.GetCertificate()
	if err != nil {
		fmt.Printf("Error getting identity certificate: %s", err.Error())
		return nil
	}

	return cert.PublicKey
}

func (i *winIdentity) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

// Close implements the Identity iterface.
func (i *winIdentity) Close() {
	if err := i._check(); err != nil {
		return
	}

	C.CertFreeCertificateContext(i.ctx)
}

func (i *winIdentity) _check() error {
	if i == nil {
		return errors.New("nil winIdentity pointer")
	}

	if i.ctx == nil {
		return errors.New("nil certificate context")
	}

	if i.closed {
		return errors.New("identity closed")
	}

	return nil
}

// winStore is a wrapper around a C.HCERTSTORE.
type winStore struct {
	store  C.HCERTSTORE
	prev   C.PCCERT_CONTEXT
	err    error
	closed bool
}

// openMyCertStore open the current user's personal cert store. Call Close()
// when finished.
func openMyCertStore() (*winStore, error) {
	storeName := C.CString("MY")
	defer C.free(unsafe.Pointer(storeName))

	store := C.CertOpenSystemStore(0, (*C.CHAR)(storeName))
	if store == nil {
		return nil, lastError()
	}

	return &winStore{store: store}, nil
}

// importCertStore imports certificates and private keys from PFX (PKCS12) data.
func importCertStore(data []byte, password string) (*winStore, error) {
	cdata := C.CBytes(data)
	defer C.free(cdata)

	cpw := stringToUTF16(password)
	defer C.free(unsafe.Pointer(cpw))

	pfx := &C.CRYPT_DATA_BLOB{
		cbData: C.DWORD(len(data)),
		pbData: (*C.BYTE)(cdata),
	}

	store := C.PFXImportCertStore(pfx, cpw, C.CRYPT_EXPORTABLE|C.PKCS12_NO_PERSIST_KEY)
	if store == nil {
		return nil, lastError()
	}

	return &winStore{store: store}, nil
}

// nextCert starts or continues an iteration through this store's certificates.
// Nil is returned once all certs have been retrieved or an error is
// encountered. Check getError() to see why iteration stopped. Iteration can be
// started over by calling reset().
func (s *winStore) nextCert() C.PCCERT_CONTEXT {
	if err := s._check(); err != nil {
		s.err = err
	}

	if s.err != nil {
		return nil
	}

	s.prev = C.CertFindCertificateInStore(
		s.store,
		C.X509_ASN_ENCODING|C.PKCS_7_ASN_ENCODING,
		0,
		C.CERT_FIND_ANY,
		nil,
		s.prev,
	)

	if s.prev == nil {
		s.err = lastError()

		return nil
	}

	return s.prev
}

// getError returns any error encountered while iterating through store's certs
// with nextCert().
func (s *winStore) getError() error {
	if err := s._check(); err != nil {
		return err
	}

	// cryptENotFound is encountered at the end of iteration or if the store
	// doesn't have any certs.
	if s.err == cryptENotFound {
		return nil
	}

	return s.err
}

// reset clears nextCert() iteration state.
func (s *winStore) reset() error {
	if err := s._check(); err != nil {
		return err
	}

	if s.prev != nil {
		C.CertFreeCertificateContext(s.prev)
	}

	s.prev = nil
	s.err = nil

	return nil
}

// Close closes this store.
func (s *winStore) Close() {
	if err := s._check(); err != nil {
		return
	}

	if s.prev != nil {
		C.CertFreeCertificateContext(s.prev)
	}

	C.CertCloseStore(s.store, 0)

	s.closed = true
}

func (s *winStore) _check() error {
	if s == nil {
		return errors.New("nil winStore pointer")
	}

	if s.store == nil {
		return errors.New("nil winStore pointer")
	}

	if s.closed {
		return errors.New("store closed")
	}

	return nil
}

type errCode C.DWORD

const (
	// cryptENotFound — Cannot find object or property.
	cryptENotFound errCode = C.CRYPT_E_NOT_FOUND & (1<<32 - 1)
)

// lastError gets the last error from the current thread.
func lastError() errCode {
	return errCode(C.GetLastError())
}

func (c errCode) Error() string {
	cmsg := C.errMsg(C.DWORD(c))
	if cmsg == nil {
		return fmt.Sprintf("Error %X", int(c))
	}
	defer C.LocalFree(C.HLOCAL(cmsg))

	gomsg := C.GoString(cmsg)

	return fmt.Sprintf("Error: %X %s", int(c), gomsg)
}

type securityStatus C.SECURITY_STATUS

func checkStatus(s C.SECURITY_STATUS) error {
	if s == C.ERROR_SUCCESS {
		return nil
	}

	return securityStatus(s)
}

func (s securityStatus) Error() string {
	return fmt.Sprintf("SECURITY_STATUS %d", int(s))
}

func stringToUTF16(s string) C.LPCWSTR {
	wstr := utf16.Encode([]rune(s))

	p := C.calloc(C.size_t(len(wstr)+1), C.size_t(unsafe.Sizeof(uint16(0))))
	pp := (*[1 << 30]uint16)(p)
	copy(pp[:], wstr)

	return (C.LPCWSTR)(p)
}
