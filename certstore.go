package main

import (
	"crypto"
	"crypto/x509"
)

// Identity is a X.509 certificate and its corresponding private key.
type Identity interface {
	// GetCertificate gets the identity's certificate.
	GetCertificate() (*x509.Certificate, error)

	// GetSigner gets a crypto.Signer that uses the identity's private key.
	GetSigner() (crypto.Signer, error)

	// Destroy deletes this identity from the system.
	Destroy() error

	// Close any manually managed memory held by the Identity.
	Close()
}
