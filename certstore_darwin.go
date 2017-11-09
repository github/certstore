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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"unsafe"
)

// macIdentity implements the Identity iterface.
type macIdentity struct {
	ref    C.SecIdentityRef
	crt    *x509.Certificate
	key    crypto.PrivateKey
	closed bool
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

// FindIdentities returns a slice of available signing identities.
func FindIdentities() ([]Identity, error) {
	query := mapToCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):      C.CFTypeRef(C.kSecClassIdentity),
		C.CFTypeRef(C.kSecReturnRef):  C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit): C.CFTypeRef(C.kSecMatchLimitAll),
	})
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

func newMacIdentity(ref C.SecIdentityRef) *macIdentity {
	C.CFRetain(C.CFTypeRef(ref))
	return &macIdentity{ref: ref}
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
	return nil, errors.New("not implemented")
}

var (
	secAttrKeyTypeRSA              = cfStringToString(C.kSecAttrKeyTypeRSA)
	secAttrKeyTypeEC               = cfStringToString(C.kSecAttrKeyTypeEC)
	secAttrKeyTypeECSECPrimeRandom = cfStringToString(C.kSecAttrKeyTypeECSECPrimeRandom)
)

// getPrivateKey implements the Identity iterface.
func (i *macIdentity) getPrivateKey() (crypto.PrivateKey, error) {
	if i.closed {
		return nil, errors.New("identity closed")
	}

	if i.ref == nil {
		return nil, errors.New("nil identity ref")
	}

	if i.key != nil {
		return i.key, nil
	}

	var keyRef C.SecKeyRef
	if err := osStatusError(C.SecIdentityCopyPrivateKey(i.ref, &keyRef)); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(keyRef))

	passphrase := C.CFTypeRef(stringToCFString("asdf"))
	defer C.CFRelease(passphrase)

	params := &C.SecItemImportExportKeyParameters{
		passphrase: passphrase,
		version:    C.SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION,
	}

	var derRef C.CFDataRef
	if err := osStatusError(C.SecItemExport(C.CFTypeRef(keyRef), C.kSecFormatWrappedOpenSSL, 0, params, &derRef)); err != nil {
		return nil, err
	}

	pemBytes := cfDataToBytes(derRef)
	blk, rest := pem.Decode(pemBytes)
	if len(rest) > 0 {
		return nil, errors.New("error decoding PEM private key")
	}

	der, err := x509.DecryptPEMBlock(blk, []byte("asdf"))
	if err != nil {
		return nil, err
	}

	attrs := C.SecKeyCopyAttributes(keyRef)
	if attrs == nil {
		return nil, errors.New("error getting private key attributes from keychain")
	}
	defer C.CFRelease(C.CFTypeRef(attrs))

	cfAlgo := C.CFDictionaryGetValue(attrs, unsafe.Pointer(C.kSecAttrKeyType))
	if cfAlgo == nil {
		return nil, errors.New("error getting private key type from keychain")
	}

	var key crypto.PrivateKey

	switch cfStringToString(C.CFStringRef(cfAlgo)) {
	case secAttrKeyTypeRSA:
		key, err = x509.ParsePKCS1PrivateKey(der)
	case secAttrKeyTypeEC, secAttrKeyTypeECSECPrimeRandom:
		key, err = x509.ParseECPrivateKey(der)
	default:
		return nil, errors.New("unkown private key type")
	}

	if err != nil {
		return nil, err
	}

	i.key = key

	return i.key, nil
}

// Close implements the Identity iterface.
func (i *macIdentity) Close() {
	if i == nil {
		return
	}

	if i.ref != nil {
		C.CFRelease(C.CFTypeRef(i.ref))
	}

	i.closed = true
}

// cfStringToString converts a CFStringRef to a Go string.
func cfStringToString(cfstr C.CFStringRef) string {
	cstr := C.CFStringGetCStringPtr(cfstr, C.kCFStringEncodingUTF8)
	if cstr == nil {
		fmt.Println("ERR: CFStringGetCStringPtr nil")
		return ""
	}

	return C.GoString(cstr)
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

// cfErrorToString converts a CFErrorRef to a Go String.
func cfErrorToString(err C.CFErrorRef) string {
	code := int(C.CFErrorGetCode(err))

	cfDescription := C.CFErrorCopyDescription(err)
	defer C.CFRelease(C.CFTypeRef(cfDescription))

	description := cfStringToString(cfDescription)

	return fmt.Sprintf("%d (%s)", code, description)
}

// cfDataToBytes converts a CFDataRef to a Go byte slice.
func cfDataToBytes(cfdata C.CFDataRef) []byte {
	nBytes := C.CFDataGetLength(cfdata)
	bytesPtr := C.CFDataGetBytePtr(cfdata)
	return C.GoBytes(unsafe.Pointer(bytesPtr), C.int(nBytes))
}

type osStatus C.OSStatus

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
