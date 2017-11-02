package main

import (
	"crypto"
	"crypto/x509"
)

// Identity is a X.509 certificate and its corresponding private key.
type Identity interface {
	// GetCertificate gets the identity's certificate.
	GetCertificate() (*x509.Certificate, error)

	// GetPrivateKey gets the identity's private key.
	GetPrivateKey() (crypto.PrivateKey, error)

	// Close any manually managed memory held by the Identity.
	Close()
}
