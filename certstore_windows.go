package main

/*
#include <windows.h>
#include <security.h>
#include <wincrypt.h>
#include <winerror.h>
*/
import "C"

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
)

type winCertStore struct {
	store C.HCERTSTORE
}

func openMyCertStore() (*winCertStore, error) {
	s := C.CertOpenSystemStore(nil, "MY")
	if s == nil {
		return nil, lastError()
	}

	return winCertStore{s}, nil
}

func (s *winCertStore) Close() {
	C.CertCloseStore(s.store)
}

// winIdentity implements the Identity iterface.
type winIdentity struct{}

func FindIdentities() ([]Identity, error) {
	store, err := openMyCertStore()
	if err != nil {
		return nil, err
	}
	defer store.Close()

	return nil, nil
}

// GetCertificate implements the Identity iterface.
func (i *winIdentity) GetCertificate() (*x509.Certificate, error) {
	return nil, errors.New("not implemented")
}

// GetPrivateKey implements the Identity iterface.
func (i *winIdentity) GetPrivateKey() (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}

// Close implements the Identity iterface.
func (i *winIdentity) Close() {}

// lastError gets the last error from the current thread.
func lastError() error {
	return errCode(C.GetLastError())
}

type errCode C.DWORD

func (c errCode) Error() string {
	return fmt.Sprintf("Error Code %d", int(c))
}
