package main

import (
	"crypto"
	"crypto/x509"
	"errors"
)

// winIdentity implements the Identity iterface.
type winIdentity struct{}

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
