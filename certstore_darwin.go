package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"unsafe"
)

// macIdentity implements the Identity iterface.
type macIdentity struct {
	ref    C.SecIdentityRef
	kref   C.SecKeyRef
	crt    *x509.Certificate
	closed bool
}

func newMacIdentity(ref C.SecIdentityRef) *macIdentity {
	C.CFRetain(C.CFTypeRef(ref))
	return &macIdentity{ref: ref}
}

// FindIdentities returns a slice of available signing identities.
func FindIdentities() ([]Identity, error) {
	query := mapToCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):      C.CFTypeRef(C.kSecClassIdentity),
		C.CFTypeRef(C.kSecReturnRef):  C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit): C.CFTypeRef(C.kSecMatchLimitAll),
	})
	if query == nil {
		return nil, errors.New("error creating CFDictionary")
	}
	defer C.CFRelease(C.CFTypeRef(query))

	var absResult C.CFTypeRef
	if err := osStatusError(C.SecItemCopyMatching(query, &absResult)); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(absResult))

	aryResult := C.CFArrayRef(absResult)
	n := C.CFArrayGetCount(aryResult)
	identRefs := make([]C.CFTypeRef, n)
	C.CFArrayGetValues(aryResult, C.CFRange{0, n}, (*unsafe.Pointer)(&identRefs[0]))

	idents := make([]Identity, 0, n)
	for _, identRef := range identRefs {
		idents = append(idents, newMacIdentity(C.SecIdentityRef(identRef)))
	}

	return idents, nil
}

func findPreferredIdentity(name string) Identity {
	cfName := stringToCFString(name)
	defer C.CFRelease(C.CFTypeRef(cfName))

	identRef := C.SecIdentityCopyPreferred(cfName, nil, nil)
	if identRef == nil {
		return nil
	}

	return newMacIdentity(identRef)
}

// GetCertificate implements the Identity iterface.
func (i *macIdentity) GetCertificate() (*x509.Certificate, error) {
	if i.closed {
		return nil, errors.New("identity closed")
	}

	if i.ref == nil {
		return nil, errors.New("nil identity ref")
	}

	if i.crt != nil {
		return i.crt, nil
	}

	var certRef C.SecCertificateRef
	if err := osStatusError(C.SecIdentityCopyCertificate(i.ref, &certRef)); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(certRef))

	derRef := C.SecCertificateCopyData(certRef)
	if derRef == nil {
		return nil, errors.New("error getting certificate from identity")
	}
	defer C.CFRelease(C.CFTypeRef(derRef))

	der := cfDataToBytes(derRef)
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("identity closed")
	}

	i.crt = crt

	return i.crt, nil
}

// GetSigner implements the Identity iterface.
func (i *macIdentity) GetSigner() (crypto.Signer, error) {
	if i.closed {
		return nil, errors.New("identity closed")
	}

	if i.ref == nil {
		return nil, errors.New("nil identity ref")
	}

	// pre-load the certificate so Public() is less likely to return nil
	// unexpectedly.
	if _, err := i.GetCertificate(); err != nil {
		return nil, err
	}

	return i, nil
}

// Destroy implements the Identity iterface.
func (i *macIdentity) Destroy() error {
	if i.closed {
		return errors.New("identity closed")
	}

	if i.ref == nil {
		return errors.New("nil identity ref")
	}

	itemList := []C.SecIdentityRef{i.ref}
	itemListPtr := (*unsafe.Pointer)(unsafe.Pointer(&itemList[0]))
	citemList := C.CFArrayCreate(nil, itemListPtr, 1, nil)
	if citemList == nil {
		return errors.New("error creating CFArray")
	}
	defer C.CFRelease(C.CFTypeRef(citemList))

	query := mapToCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):         C.CFTypeRef(C.kSecClassIdentity),
		C.CFTypeRef(C.kSecMatchItemList): C.CFTypeRef(citemList),
	})
	if query == nil {
		return errors.New("error creating CFDictionary")
	}
	defer C.CFRelease(C.CFTypeRef(query))

	if err := osStatusError(C.SecItemDelete(query)); err != nil {
		return err
	}

	return nil
}

// Close implements the Identity iterface.
func (i *macIdentity) Close() {
	if i == nil {
		return
	}

	if i.ref != nil {
		C.CFRelease(C.CFTypeRef(i.ref))
	}

	if i.kref != nil {
		C.CFRelease(C.CFTypeRef(i.kref))
	}

	i.closed = true
}

// Public implements the crypto.Signer iterface.
func (i *macIdentity) Public() crypto.PublicKey {
	cert, err := i.GetCertificate()
	if err != nil {
		return nil
	}

	return cert.PublicKey
}

// Sign implements the crypto.Signer iterface.
func (i *macIdentity) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()

	if len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}

	kref, err := i.getKeyRef()
	if err != nil {
		return nil, err
	}

	cdigest, err := bytesToCFData(digest)
	if err != nil {
		return nil, err
	}

	algo, err := i.getAlgo(hash)
	if err != nil {
		return nil, err
	}

	// sign the digest
	var cerr C.CFErrorRef
	csig := C.SecKeyCreateSignature(kref, algo, cdigest, &cerr)

	if err := cfErrorError(cerr); err != nil {
		return nil, err
	}

	if csig == nil {
		return nil, errors.New("nil signature from SecKeyCreateSignature")
	}

	defer C.CFRelease(C.CFTypeRef(csig))

	sig := cfDataToBytes(csig)

	return sig, nil
}

// getAlgo decides which algorithm to use with this key type for the given hash.
func (i *macIdentity) getAlgo(hash crypto.Hash) (algo C.SecKeyAlgorithm, err error) {
	var crt *x509.Certificate
	if crt, err = i.GetCertificate(); err != nil {
		return
	}

	switch crt.PublicKey.(type) {
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA1:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA1
		case crypto.SHA256:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256
		case crypto.SHA384:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA384
		case crypto.SHA512:
			algo = C.kSecKeyAlgorithmECDSASignatureDigestX962SHA512
		default:
			err = errors.New("unsupported hash algorithm")
		}
	case *rsa.PublicKey:
		switch hash {
		case crypto.SHA1:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1
		case crypto.SHA256:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
		case crypto.SHA384:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384
		case crypto.SHA512:
			algo = C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512
		default:
			err = errors.New("unsupported hash algorithm")
		}
	default:
		err = errors.New("unsupported key type")
	}

	return
}

// getKeyRef gets the SecKeyRef for this identity's pricate key.
func (i *macIdentity) getKeyRef() (C.SecKeyRef, error) {
	if i.closed {
		return nil, errors.New("identity closed")
	}

	if i.ref == nil {
		return nil, errors.New("nil identity ref")
	}

	if i.kref != nil {
		return i.kref, nil
	}

	var keyRef C.SecKeyRef
	if err := osStatusError(C.SecIdentityCopyPrivateKey(i.ref, &keyRef)); err != nil {
		return nil, err
	}

	i.kref = keyRef

	return i.kref, nil
}

// stringToCFString converts a Go string to a CFStringRef.
func stringToCFString(gostr string) C.CFStringRef {
	cstr := C.CString(gostr)
	defer C.free(unsafe.Pointer(cstr))

	return C.CFStringCreateWithCString(nil, cstr, C.kCFStringEncodingUTF8)
}

// mapToCFDictionary converts a Go map[C.CFTypeRef]C.CFTypeRef to a
// CFDictionaryRef.
func mapToCFDictionary(gomap map[C.CFTypeRef]C.CFTypeRef) C.CFDictionaryRef {
	var (
		n      = len(gomap)
		keys   = make([]unsafe.Pointer, 0, n)
		values = make([]unsafe.Pointer, 0, n)
	)

	for k, v := range gomap {
		keys = append(keys, unsafe.Pointer(k))
		values = append(values, unsafe.Pointer(v))
	}

	return C.CFDictionaryCreate(nil, &keys[0], &values[0], C.CFIndex(n), nil, nil)
}

// cfDataToBytes converts a CFDataRef to a Go byte slice.
func cfDataToBytes(cfdata C.CFDataRef) []byte {
	nBytes := C.CFDataGetLength(cfdata)
	bytesPtr := C.CFDataGetBytePtr(cfdata)
	return C.GoBytes(unsafe.Pointer(bytesPtr), C.int(nBytes))
}

// bytesToCFData converts a Go byte slice to a CFDataRef.
func bytesToCFData(gobytes []byte) (C.CFDataRef, error) {
	var (
		cptr = (*C.UInt8)(nil)
		clen = C.CFIndex(len(gobytes))
	)

	if len(gobytes) > 0 {
		cptr = (*C.UInt8)(&gobytes[0])
	}

	cdata := C.CFDataCreate(nil, cptr, clen)
	if cdata == nil {
		return nil, errors.New("error creatin cfdata")
	}

	return cdata, nil
}

// osStatus wraps a C.OSStatus
type osStatus C.OSStatus

// osStatusError returns an error for an OSStatus unless it is errSecSuccess.
func osStatusError(s C.OSStatus) error {
	if s == C.errSecSuccess {
		return nil
	}

	return osStatus(s)
}

// Error implements the error interface.
func (s osStatus) Error() string {
	return fmt.Sprintf("OSStatus %d", s)
}

// cfErrorError returns an error for a CFErrorRef unless it is nil.
func cfErrorError(cerr C.CFErrorRef) error {
	if cerr == nil {
		return nil
	}

	code := int(C.CFErrorGetCode(cerr))

	if cdescription := C.CFErrorCopyDescription(cerr); cdescription != nil {
		defer C.CFRelease(C.CFTypeRef(cdescription))

		if cstr := C.CFStringGetCStringPtr(cdescription, C.kCFStringEncodingUTF8); cstr != nil {
			str := C.GoString(cstr)

			return fmt.Errorf("CFError %d (%s)", code, str)
		}

	}

	return fmt.Errorf("CFError %d", code)
}
