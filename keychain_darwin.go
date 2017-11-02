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
	"fmt"
	"unsafe"
)

type certificate struct {
	ref    C.SecCertificateRef
	crt    *x509.Certificate
	closed bool
}

func (c *certificate) get() *x509.Certificate {
	if c.closed {
		return nil
	}

	if c.crt != nil {
		return c.crt
	}

	derRef := C.SecCertificateCopyData(c.ref)
	if derRef == nil {
		fmt.Println("ERR: SecCertificateCopyData nil")
		return nil
	}
	defer C.CFRelease(C.CFTypeRef(derRef))

	nBytes := C.int((C.CFDataGetLength(derRef)))
	bytesPtr := C.CFDataGetBytePtr(derRef)
	der := C.GoBytes(unsafe.Pointer(bytesPtr), nBytes)

	crt, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	c.crt = crt

	return c.crt
}

func (c *certificate) Close() {
	if c == nil || c.closed {
		return
	}

	if c.ref != nil {
		C.CFRelease(C.CFTypeRef(c.ref))
	}

	c.closed = true
}

type privateKey struct {
	ref    C.SecKeyRef
	key    crypto.PrivateKey
	closed bool
}

var (
	secAttrKeyTypeRSA              = cfStringToString(C.kSecAttrKeyTypeRSA)
	secAttrKeyTypeEC               = cfStringToString(C.kSecAttrKeyTypeEC)
	secAttrKeyTypeECSECPrimeRandom = cfStringToString(C.kSecAttrKeyTypeECSECPrimeRandom)
)

func (k *privateKey) get() crypto.PrivateKey {
	if k.closed {
		return nil
	}

	if k.key != nil {
		return k.key
	}

	passphrase := C.CFTypeRef(stringToCFString("asdf"))
	defer C.CFRelease(passphrase)

	params := &C.SecItemImportExportKeyParameters{
		passphrase: passphrase,
		version:    C.SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION,
	}

	var derRef C.CFDataRef

	if err := C.SecItemExport(C.CFTypeRef(k.ref), C.kSecFormatWrappedOpenSSL, 0, params, &derRef); err != C.errSecSuccess {
		fmt.Println("ERR: SecItemExport ", err)
		return nil
	}

	nBytes := C.int((C.CFDataGetLength(derRef)))
	bytesPtr := C.CFDataGetBytePtr(derRef)
	pemBytes := C.GoBytes(unsafe.Pointer(bytesPtr), nBytes)

	blk, rest := pem.Decode(pemBytes)
	if len(rest) > 0 {
		panic("error decoding key from keychain")
	}

	der, err := x509.DecryptPEMBlock(blk, []byte("asdf"))
	if err != nil {
		fmt.Println("ERR: DecryptPEMBlock ", err)
		return nil
	}

	attrs := C.SecKeyCopyAttributes(k.ref)
	if attrs == nil {
		fmt.Println("ERR: SecKeyCopyAttributes nil")
		return nil
	}
	defer C.CFRelease(C.CFTypeRef(attrs))

	cfAlgo := C.CFDictionaryGetValue(attrs, unsafe.Pointer(C.kSecAttrKeyType))
	if cfAlgo == nil {
		fmt.Println("ERR: CFDictionaryGetValue nil")
		return nil
	}

	var key crypto.PrivateKey

	switch cfStringToString(C.CFStringRef(cfAlgo)) {
	case secAttrKeyTypeRSA:
		key, err = x509.ParsePKCS1PrivateKey(der)
	case secAttrKeyTypeEC, secAttrKeyTypeECSECPrimeRandom:
		key, err = x509.ParseECPrivateKey(der)
	default:
		panic("ERR: unknown private key algorithm")
	}

	if err != nil {
		panic(err)
	}

	k.key = key

	return k.key
}

func (k *privateKey) Close() {
	if k == nil || k.closed {
		return
	}

	if k.ref != nil {
		C.CFRelease(C.CFTypeRef(k.ref))
	}

	k.closed = true
}

type identity struct {
	ref    C.SecIdentityRef
	cert   *certificate
	key    *privateKey
	closed bool
}

func findPreferredIdentity(name string) *identity {
	cfName := stringToCFString(name)
	defer C.CFRelease(C.CFTypeRef(cfName))

	identRef := C.SecIdentityCopyPreferred(cfName, nil, nil)
	if identRef == nil {
		fmt.Println("ERR: SecIdentityCopyPreferred nil")
		return nil
	}

	return newIdentity(identRef)
}

func findIdentities() []*identity {
	query := mapToCFDictionary(map[C.CFTypeRef]C.CFTypeRef{
		C.CFTypeRef(C.kSecClass):      C.CFTypeRef(C.kSecClassIdentity),
		C.CFTypeRef(C.kSecReturnRef):  C.CFTypeRef(C.kCFBooleanTrue),
		C.CFTypeRef(C.kSecMatchLimit): C.CFTypeRef(C.kSecMatchLimitAll),
	})
	defer C.CFRelease(C.CFTypeRef(query))

	var absResult C.CFTypeRef
	if err := C.SecItemCopyMatching(query, &absResult); err != C.errSecSuccess {
		fmt.Println("ERR: SecItemCopyMatching ", err)
		return nil
	}
	defer C.CFRelease(C.CFTypeRef(absResult))

	aryResult := C.CFArrayRef(absResult)
	n := C.CFArrayGetCount(aryResult)
	identRefs := make([]C.CFTypeRef, n)
	C.CFArrayGetValues(aryResult, C.CFRange{0, n}, (*unsafe.Pointer)(&identRefs[0]))

	idents := make([]*identity, 0, n)
	for _, identRef := range identRefs {
		idents = append(idents, newIdentity(C.SecIdentityRef(identRef)))
		C.CFRetain(identRef)
	}

	return idents
}

func newIdentity(ref C.SecIdentityRef) *identity {
	return &identity{ref: ref}
}

func (i *identity) getCertificate() *certificate {
	if i.closed {
		return nil
	}

	if i.cert != nil {
		return i.cert
	}

	cert := new(certificate)

	if err := C.SecIdentityCopyCertificate(i.ref, &cert.ref); err != C.errSecSuccess {
		fmt.Println("ERR: SecIdentityCopyCertificate ", err)
		return nil
	}

	i.cert = cert

	return cert
}

func (i *identity) getPrivateKey() *privateKey {
	if i.closed {
		return nil
	}

	if i.key != nil {
		return i.key
	}

	key := new(privateKey)

	if err := C.SecIdentityCopyPrivateKey(i.ref, &key.ref); err != C.errSecSuccess {
		fmt.Println("ERR: SecIdentityCopyPrivateKey ", err)
		return nil
	}

	i.key = key

	return key
}

func (i *identity) Close() {
	if i == nil {
		return
	}

	if i.ref != nil {
		C.CFRelease(C.CFTypeRef(i.ref))
	}

	i.cert.Close()
	i.key.Close()

	i.closed = true
}

func stringToCFString(gostr string) C.CFStringRef {
	cstr := C.CString(gostr)
	defer C.free(unsafe.Pointer(cstr))

	return C.CFStringCreateWithCString(nil, cstr, C.kCFStringEncodingUTF8)
}

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

func cfErrorToString(err C.CFErrorRef) string {
	code := int(C.CFErrorGetCode(err))

	cfDescription := C.CFErrorCopyDescription(err)
	defer C.CFRelease(C.CFTypeRef(cfDescription))

	description := cfStringToString(cfDescription)

	return fmt.Sprintf("%d (%s)", code, description)
}

func cfStringToString(cfstr C.CFStringRef) string {
	cstr := C.CFStringGetCStringPtr(cfstr, C.kCFStringEncodingUTF8)
	if cstr == nil {
		fmt.Println("ERR: CFStringGetCStringPtr nil")
		return ""
	}

	return C.GoString(cstr)
}
