package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"unsafe"
)

type certificate struct {
	ref    C.SecCertificateRef
	der    []byte
	closed bool
}

func (c *certificate) getDER() []byte {
	if c.closed {
		return nil
	}

	if c.der != nil {
		return c.der
	}

	derRef := C.SecCertificateCopyData(c.ref)
	if derRef == nil {
		fmt.Println("ERR: SecCertificateCopyData nil")
		return nil
	}
	defer C.CFRelease(C.CFTypeRef(derRef))

	nBytes := C.int((C.CFDataGetLength(derRef)))
	bytesPtr := C.CFDataGetBytePtr(derRef)
	c.der = C.GoBytes(unsafe.Pointer(bytesPtr), nBytes)

	return c.der
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
	der    []byte
	closed bool
}

func (k *privateKey) getDER() []byte {
	if k.closed {
		return nil
	}

	if k.der != nil {
		return k.der
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

	var err error
	if k.der, err = x509.DecryptPEMBlock(blk, []byte("asdf")); err != nil {
		panic(err)
	}

	return k.der
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

	cDescription := C.CFStringGetCStringPtr(cfDescription, C.kCFStringEncodingUTF8)
	defer C.free(unsafe.Pointer(cDescription))

	description := C.GoString(cDescription)

	return fmt.Sprintf("%d (%s)", code, description)
}
