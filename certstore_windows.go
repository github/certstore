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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
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

	f, _ := os.Create("eccert.der")
	f.Write(der)
	f.Close()

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

// GetPrivateKey implements the Identity iterface.
func (i *winIdentity) GetPrivateKey() (crypto.PrivateKey, error) {
	if err := i._check(); err != nil {
		return nil, err
	}

	var (
		key      C.HCRYPTPROV_OR_NCRYPT_KEY_HANDLE
		keySpec  C.DWORD
		mustFree C.WINBOOL
	)

	if ok := C.CryptAcquireCertificatePrivateKey(i.ctx, C.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|C.CRYPT_ACQUIRE_CACHE_FLAG, nil, &key, &keySpec, &mustFree); ok == winFalse {
		return nil, lastError()
	}

	if keySpec == C.CERT_NCRYPT_KEY_SPEC {
		// The key is a CNG key.

		cngKey := C.NCRYPT_HANDLE(key)
		if mustFree == winTrue {
			defer C.NCryptFreeObject(cngKey)
		}

		return exportNCryptPrivateKey(cngKey)

	} else {
		// The key is a CryptoAPI provider.
		fmt.Println("caKey")

		caProv := C.HCRYPTPROV(key)
		if mustFree == winTrue {
			defer C.CryptReleaseContext(caProv, 0)
		}

		var caKey C.HCRYPTKEY
		if ok := C.CryptGetUserKey(caProv, keySpec, &caKey); ok == winFalse {
			return nil, lastError()
		}

		var dataLen C.DWORD
		if ok := C.CryptExportKey(caKey, 0, C.PRIVATEKEYBLOB, 0, nil, &dataLen); ok == winFalse {
			return nil, lastError()
		}

		data := make([]C.BYTE, dataLen)
		if ok := C.CryptExportKey(caKey, 0, C.PRIVATEKEYBLOB, 0, &data[0], &dataLen); ok == winFalse {
			return nil, lastError()
		}

		fmt.Printf("key is %d bytes\n", dataLen)
	}

	return nil, errors.New("not implemented")
}

// exportNCryptPrivateKey tries to export a CNG private key.
func exportNCryptPrivateKey(handle C.NCRYPT_HANDLE) (crypto.PrivateKey, error) {
	// Try marking the key as exportable
	var exportPolicy C.DWORD = C.NCRYPT_ALLOW_EXPORT_FLAG | C.NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
	if err := ncryptSetProperty(handle, NCRYPT_EXPORT_POLICY_PROPERTY, dwordToByteSlice(exportPolicy)); err != nil {
		panic(err)
	}

	// Check that the key *is* exportable.
	if canExport, err := canExportNCryptPrivateKey(handle); err != nil {
		return nil, err
	} else if !canExport {
		return nil, errors.New("key is marked non-exportable")
	}

	algo, err := ncryptGetPropertyUTF16(handle, NCRYPT_ALGORITHM_GROUP_PROPERTY)
	if err != nil {
		return nil, err
	}

	switch algo {
	case "RSA":
		return ncryptExportRSAKey(handle)
	case "ECDSA", "ECDH":
		return ncryptExportECDSAKey(handle)
	default:
		return nil, fmt.Errorf("unsupported algorithm '%s'", algo)
	}
}

// canExportNCryptPrivateKey checks if a key is marked exportable.
func canExportNCryptPrivateKey(handle C.NCRYPT_HANDLE) (bool, error) {
	var (
		policy C.DWORD = C.NCRYPT_ALLOW_EXPORT_FLAG | C.NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
		nBytes C.DWORD

		policyPtr  = (*C.BYTE)(unsafe.Pointer(&policy))
		policySize = C.DWORD(unsafe.Sizeof(policy))
	)

	if err := checkStatus(C.NCryptGetProperty(handle, NCRYPT_EXPORT_POLICY_PROPERTY, policyPtr, policySize, &nBytes, 0)); err != nil {
		return false, err
	}

	if nBytes != policySize {
		return false, errors.New("bad output from NCryptGetProperty")
	}

	canExport := policy&C.NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG > 0

	return canExport, nil
}

// ncryptGetProperty gets the given property for an ncrypt object as a UTF16
// string.
func ncryptGetPropertyUTF16(handle C.NCRYPT_HANDLE, property C.LPCWSTR) (string, error) {
	value, err := ncryptGetProperty(handle, property)
	if err != nil {
		return "", err
	}

	if len(value)%2 != 0 || len(value) < 2 {
		return "", errors.New("bad value length from NCryptGetProperty")
	}

	if value[len(value)-1] != 0 || value[len(value)-2] != 0 {
		return "", errors.New("non null terminated string from NCryptGetProperty")
	}

	// remove trailing \0
	value = value[:len(value)-2]

	// convert to byte->uint16
	value16 := make([]uint16, len(value)/2)
	for i := 0; i < len(value); i += 2 {
		value16[i/2] = nativeByteOrder.Uint16(value[i : i+2])
	}

	return string(utf16.Decode(value16)), nil
}

// ncryptGetProperty gets the given property for an ncrypt object.
func ncryptGetProperty(handle C.NCRYPT_HANDLE, property C.LPCWSTR) ([]byte, error) {
	var cbOutput C.DWORD
	if err := checkStatus(C.NCryptGetProperty(handle, property, nil, 0, &cbOutput, 0)); err != nil {
		return nil, err
	}

	var (
		output    = make([]byte, int(cbOutput))
		outputPtr = (*C.BYTE)(unsafe.Pointer(&output[0]))
	)
	if err := checkStatus(C.NCryptGetProperty(handle, property, outputPtr, cbOutput, &cbOutput, 0)); err != nil {
		return nil, err
	}

	return output, nil
}

// ncryptSetProperty sets the given property for an ncrypt object.
func ncryptSetProperty(handle C.NCRYPT_HANDLE, property C.LPCWSTR, value []byte) error {
	var (
		valuePtr  = (*C.BYTE)(unsafe.Pointer(&value[0]))
		valueSize = C.DWORD(len(value))
	)

	return checkStatus(C.NCryptSetProperty(handle, property, valuePtr, valueSize, 0))
}

// ncryptExportRSAKey exports an RSA key.
func ncryptExportRSAKey(handle C.NCRYPT_HANDLE) (*rsa.PrivateKey, error) {
	blob, err := ncryptExportKeyBlob(handle, BCRYPT_RSAFULLPRIVATE_BLOB)
	if err != nil {
		return nil, err
	}

	hdrLen := int(unsafe.Sizeof(C.BCRYPT_RSAKEY_BLOB{}))
	if len(blob) < hdrLen {
		return nil, errors.New("bad output from NCryptExportKey")
	}

	hdr := (*C.BCRYPT_RSAKEY_BLOB)(unsafe.Pointer(&blob[0]))

	var (
		publicExponentOffset = hdrLen
		publicExponentLen    = int(hdr.cbPublicExp)

		modulusOffset = publicExponentOffset + publicExponentLen
		modulusLen    = int(hdr.cbModulus)

		prime1Offset = modulusOffset + modulusLen
		prime1Len    = int(hdr.cbPrime1)

		prime2Offset = prime1Offset + prime1Len
		prime2Len    = int(hdr.cbPrime2)

		exponent1Offset = prime2Offset + prime2Len
		exponent1Len    = int(hdr.cbPrime1)

		exponent2Offset = exponent1Offset + exponent1Len
		exponent2Len    = int(hdr.cbPrime2)

		coefficientOffset = exponent2Offset + exponent2Len
		coefficientLen    = int(hdr.cbPrime1)

		privateExponentOffset = coefficientOffset + coefficientLen
		privateExponentLen    = int(hdr.cbModulus)
	)

	if len(blob) < privateExponentOffset+privateExponentLen {
		return nil, errors.New("bad output from NCryptExportKey")
	}

	e := new(big.Int)
	e.SetBytes(blob[publicExponentOffset : publicExponentOffset+publicExponentLen])

	n := new(big.Int)
	n.SetBytes(blob[modulusOffset : modulusOffset+modulusLen])

	p := new(big.Int)
	p.SetBytes(blob[prime1Offset : prime1Offset+prime1Len])

	q := new(big.Int)
	q.SetBytes(blob[prime2Offset : prime2Offset+prime2Len])

	d := new(big.Int)
	d.SetBytes(blob[privateExponentOffset : privateExponentOffset+privateExponentLen])

	k := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{E: int(e.Int64()), N: n},
		Primes:    []*big.Int{p, q},
		D:         d,
	}

	if err := k.Validate(); err != nil {
		return nil, err
	}

	return k, nil
}

// ncryptExportECDSAKey exports an ECDSA key.
func ncryptExportECDSAKey(handle C.NCRYPT_HANDLE) (*ecdsa.PrivateKey, error) {
	blob, err := ncryptExportKeyBlob(handle, BCRYPT_ECCPRIVATE_BLOB)
	if err != nil {
		return nil, err
	}

	hdrLen := int(unsafe.Sizeof(C.BCRYPT_ECCKEY_BLOB{}))
	if len(blob) < hdrLen {
		return nil, errors.New("bad output from NCryptExportKey")
	}

	hdr := (*C.BCRYPT_ECCKEY_BLOB)(unsafe.Pointer(&blob[0]))

	var curve elliptic.Curve

	switch hdr.dwMagic {
	case C.BCRYPT_ECDSA_PRIVATE_P256_MAGIC, C.BCRYPT_ECDH_PRIVATE_P256_MAGIC:
		curve = elliptic.P256()
	case C.BCRYPT_ECDSA_PRIVATE_P384_MAGIC, C.BCRYPT_ECDH_PRIVATE_P384_MAGIC:
		curve = elliptic.P384()
	case C.BCRYPT_ECDSA_PRIVATE_P521_MAGIC, C.BCRYPT_ECDH_PRIVATE_P521_MAGIC:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unknown elliptic key %X", int(hdr.dwMagic))
	}

	var (
		kLen    = int(hdr.cbKey)
		xOffset = hdrLen
		yOffset = xOffset + kLen
		dOffset = yOffset + kLen
	)

	if len(blob) < dOffset+kLen {
		return nil, errors.New("bad output from NCryptExportKey")
	}

	x := new(big.Int)
	x.SetBytes(blob[xOffset : xOffset+kLen])

	y := new(big.Int)
	y.SetBytes(blob[yOffset : yOffset+kLen])

	d := new(big.Int)
	d.SetBytes(blob[dOffset : dOffset+kLen])

	k := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}

	return k, nil
}

// ncryptExportKeyBlob exports a key with the given format.
func ncryptExportKeyBlob(handle C.NCRYPT_HANDLE, format C.LPCWSTR) ([]byte, error) {
	key := C.NCRYPT_KEY_HANDLE(handle)

	var dataLen C.DWORD
	if err := checkStatus(C.NCryptExportKey(key, 0, format, nil, nil, 0, &dataLen, 0)); err != nil {
		return nil, err
	}

	var (
		data    = make([]byte, dataLen)
		dataPtr = (*C.BYTE)(&data[0])
	)

	if err := checkStatus(C.NCryptExportKey(key, 0, format, nil, dataPtr, dataLen, &dataLen, 0)); err != nil {
		return nil, err
	}

	return data, nil
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
	alg    C.BCRYPT_ALG_HANDLE
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

	return newWinStore(store)
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

	return newWinStore(store)
}

func newWinStore(store C.HCERTSTORE) (*winStore, error) {
	var algHandle C.BCRYPT_ALG_HANDLE

	if status := C.BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_ECDSA_ALGORITHM, nil, 0); status != 0 {
		C.CertCloseStore(store, 0)
		return nil, fmt.Errorf("Error opening ECDSA algorithm provider (%d)", int(status))
	}

	return &winStore{store: store, alg: algHandle}, nil
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

	if s.alg != nil {
		C.BCryptCloseAlgorithmProvider(s.alg, 0)
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

func dwordToByteSlice(w C.DWORD) []byte {
	b := make([]byte, 4)
	nativeByteOrder.PutUint32(b, uint32(w))
	return b
}
