package certstore

/*
#cgo pkg-config: nss
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>

#include <nss.h>
#include <cryptohi.h>
#include <nspr.h>
#include <p12.h>
#include <p12plcy.h>
#include <pk11pub.h>
#include <prerror.h>
#include <secerr.h>

SECItem *P12U_NicknameCollisionCallback(SECItem *old_nick, PRBool *cancel, void *wincx) {
	char *nick = NULL;
	SECItem *ret_nick = NULL;
	CERTCertificate *cert = (CERTCertificate *)wincx;
	if (!cancel || !cert) {
		return NULL;
	}
	nick = CERT_MakeCANickname(cert);
	if (!nick) {
		return NULL;
	}
	if (old_nick && old_nick->data && old_nick->len &&
		PORT_Strlen(nick) == old_nick->len - 1 &&
		!PORT_Strncmp((char *)old_nick->data, nick, old_nick->len - 1)) {
		PORT_Free(nick);
		return NULL;
    }
	ret_nick = PORT_ZNew(SECItem);
	if (ret_nick == NULL) {
		PORT_Free(nick);
		return NULL;
	}
	ret_nick->data = (unsigned char *)nick;
	ret_nick->len = PORT_Strlen(nick) + 1;
	return ret_nick;
}

CERTCertListNode *CertListHead(CERTCertList *l) {
	return CERT_LIST_HEAD(l);
}

CERTCertListNode *CertListNext(CERTCertListNode *n) {
	return CERT_LIST_NEXT(n);
}

int CertListEnd(CERTCertListNode *n, CERTCertList *l) {
	return CERT_LIST_END(n, l);
}

const char *GetErrorString() {
	return PORT_ErrorToString(PORT_GetError());
}

void EnablePKCS12Algorithms() {
	SEC_PKCS12EnableCipher(PKCS12_RC4_40, 1);
	SEC_PKCS12EnableCipher(PKCS12_RC4_128, 1);
	SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_40, 1);
	SEC_PKCS12EnableCipher(PKCS12_RC2_CBC_128, 1);
	SEC_PKCS12EnableCipher(PKCS12_DES_56, 1);
	SEC_PKCS12EnableCipher(PKCS12_DES_EDE3_168, 1);
#ifdef PKCS12_AES_CBC_128
	SEC_PKCS12EnableCipher(PKCS12_AES_CBC_128, 1);
	SEC_PKCS12EnableCipher(PKCS12_AES_CBC_192, 1);
	SEC_PKCS12EnableCipher(PKCS12_AES_CBC_256, 1);
#endif
	SEC_PKCS12SetPreferredCipher(PKCS12_DES_EDE3_168, 1);
}
*/
import "C"
import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"unicode/utf16"
	"unsafe"
)

// Map go hash algorithm identifiers to NSS's SECOidTags
var goToNssAlg = map[crypto.Hash]C.SECOidTag{
	crypto.SHA1:   C.SEC_OID_SHA1,
	crypto.SHA256: C.SEC_OID_SHA256,
	crypto.SHA384: C.SEC_OID_SHA384,
	crypto.SHA512: C.SEC_OID_SHA512,
}

// nssStore is a wrapper around a C.NSSInitContext
type nssStore C.NSSInitContext

// Identities implements the Store interface.
func (store nssStore) Identities() ([]Identity, error) {
	var (
		identities = make([]Identity, 0)
		certs      = C.PK11_ListCerts(C.PK11CertListUser, nil)
	)
	if certs == nil {
		return nil, fmt.Errorf("error listing user certificates: %s", C.GoString(C.GetErrorString()))
	}
	defer C.CERT_DestroyCertList(certs)
	for node := C.CertListHead(certs); C.CertListEnd(node, certs) == 0; node = C.CertListNext(node) {
		identities = append(identities, (*nssIdentity)(C.CERT_DupCertificate(node.cert)))
	}
	return identities, nil
}

// nssIdentity is a wrapper around a C.CERTCertificate.
type nssIdentity C.CERTCertificate

// Signer implements the Identity interface.
func (i *nssIdentity) Signer() (crypto.Signer, error) {
	return i, nil
}

// Certificate implements the Identity interface.
func (i *nssIdentity) Certificate() (*x509.Certificate, error) {
	var (
		der   = i.derCert
		bytes = C.GoBytes(unsafe.Pointer(der.data), C.int(der.len))
	)
	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// CertificateChain implements the Identity interface.
func (i *nssIdentity) CertificateChain() ([]*x509.Certificate, error) {
	certs := C.CERT_GetCertChainFromCert((*C.CERTCertificate)(i), C.PR_Now(), C.certUsageAnyCA)
	if certs == nil {
		return nil, fmt.Errorf("error building certificate chain: %s", C.GoString(C.GetErrorString()))
	}
	defer C.CERT_DestroyCertList(certs)

	certificates := make([]*x509.Certificate, 0)
	for node := C.CertListHead(certs); C.CertListEnd(node, certs) == 0; node = C.CertListNext(node) {
		cert, err := (*nssIdentity)(node.cert).Certificate()
		if err != nil {
			return nil, errors.New("unable to parse certificate when building chain")
		}
		certificates = append(certificates, cert)
	}
	return certificates, nil
}

// Delete implements the Identity interface.
func (i *nssIdentity) Delete() error {
	secstatus := C.PK11_DeleteTokenCertAndKey((*C.CERTCertificate)(i), nil)
	if secstatus != C.SECSuccess {
		return errors.New("failed to delete certificate & key pair")
	}
	return nil
}

// Close implements the Identity interface.
func (i *nssIdentity) Close() {
	C.CERT_DestroyCertificate((*C.CERTCertificate)(i))
}

// Public implements the crypto.Signer interface.
func (i *nssIdentity) Public() crypto.PublicKey {
	cert, _ := i.Certificate()
	if cert == nil {
		return nil
	}
	return cert.PublicKey
}

// Sign implements the crypto.Signer interface.
func (i *nssIdentity) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}
	key := C.PK11_FindKeyByAnyCert((*C.CERTCertificate)(i), nil)
	if key == nil {
		return nil, errors.New("cannot find private key")
	}
	defer C.SECKEY_DestroyPrivateKey(key)

	digestC := C.SECITEM_AllocItem(nil, nil, C.uint(len(digest)))
	if digestC == nil {
		return nil, errors.New("failure to allocate memory for digest")
	}
	defer C.SECITEM_FreeItem(digestC, 1)

	resultC := C.SECITEM_AllocItem(nil, nil, C.uint(C.PK11_SignatureLen(key)))
	if resultC == nil {
		return nil, errors.New("failure to allocate memory for signature")
	}
	defer C.SECITEM_FreeItem(resultC, 1)

	digestC.len = C.uint(len(digest))
	C.memcpy(unsafe.Pointer(digestC.data), unsafe.Pointer(&digest[0]), C.size_t(len(digest)))

	if C.SGN_Digest(key, goToNssAlg[hash], resultC, digestC) != C.SECSuccess {
		if C.PORT_GetError() == C.SEC_ERROR_INVALID_ALGORITHM {
			return nil, ErrUnsupportedHash
		}
		return nil, fmt.Errorf("error signing: %s", C.GoString(C.GetErrorString()))
	}

	if key.keyType == C.ecKey {
		var dsaSig C.SECItem
		if C.DSAU_EncodeDerSigWithLen(&dsaSig, resultC, resultC.len) != C.SECSuccess {
			return nil, errors.New("unable to generate dsa signature")
		}
		resultC = &dsaSig
	}
	return C.GoBytes(unsafe.Pointer(resultC.data), C.int(resultC.len)), nil
}

// Import implements the Store interface.
func (nssStore) Import(data []byte, password string) error {
	unicodePassword, err := bmpString(password)
	if unicodePassword == nil {
		return err
	}
	pass := C.SECITEM_AllocItem(nil, nil, C.uint(len(unicodePassword)))
	if pass == nil {
		return errors.New("error allocating memory for PKCS#12 password")
	}
	defer C.SECITEM_FreeItem(pass, 1)
	C.memcpy(unsafe.Pointer(pass.data), unsafe.Pointer(&unicodePassword[0]), C.size_t(len(unicodePassword)))
	p12 := C.SEC_PKCS12DecoderStart(pass, nil, nil, nil, nil, nil, nil, nil)
	if p12 == nil {
		return fmt.Errorf("error initialising PKCS#12 decoding: %s", C.GoString(C.GetErrorString()))
	}
	decoded := C.SEC_PKCS12DecoderUpdate(p12, (*C.uchar)(unsafe.Pointer(&data[0])), C.ulong(len(data)))
	if decoded != C.SECSuccess {
		return fmt.Errorf("error during PKCS#12 decoding: %s", C.GoString(C.GetErrorString()))
	}
	authenticated := C.SEC_PKCS12DecoderVerify(p12)
	if authenticated != C.SECSuccess {
		return fmt.Errorf("error during PKCS#12 verification: %s", C.GoString(C.GetErrorString()))
	}
	validated := C.SEC_PKCS12DecoderValidateBags(p12, (*[0]byte)(C.P12U_NicknameCollisionCallback))
	if validated != C.SECSuccess {
		return fmt.Errorf("error during PKCS#12 bag validation: %s", C.GoString(C.GetErrorString()))
	}
	imported := C.SEC_PKCS12DecoderImportBags(p12)
	if imported != 0 {
		return fmt.Errorf("error during PKCS#12 import: %s", C.GoString(C.GetErrorString()))
	}
	return nil
}

// Close implements the Store interface.
func (store nssStore) Close() {
	nssCtx := C.NSSInitContext(store)
	C.NSS_ShutdownContext(&nssCtx)
}

// openStore opens the current user's NSS database.
func openStore() (Store, error) {
	homeDir := os.Getenv("HOME")

	if homeDir == "" {
		return nil, errors.New("the HOME environment variable is not defined")
	}

	nssdb := path.Join(homeDir, ".pki", "nssdb")
	if _, err := os.Stat(nssdb); os.IsNotExist(err) {
		return nil, fmt.Errorf("NSS database not found at %s", nssdb)
	}

	var (
		nssdbC       = C.CString(nssdb)
		emptyStringC = C.CString("")
	)
	defer C.free(unsafe.Pointer(nssdbC))
	defer C.free(unsafe.Pointer(emptyStringC))

	ctx := C.NSS_InitContext(nssdbC, emptyStringC, emptyStringC, emptyStringC, nil, C.PRUint32(0))
	if ctx == nil {
		return nil, fmt.Errorf("error opening NSS database %s: %s", nssdb, C.GoString(C.GetErrorString()))
	}
	C.EnablePKCS12Algorithms()
	return nssStore(*ctx), nil
}

// bmpString encodes a string into a UCS-2 bytestream.
func bmpString(s string) ([]byte, error) {
	ret := make([]byte, 0, 2*len(s)+2)
	for _, r := range s {
		if t, _ := utf16.EncodeRune(r); t != 0xfffd {
			return nil, errors.New("pkcs12: string contains characters that cannot be encoded in UCS-2")
		}
		ret = append(ret, byte(r/256), byte(r%256))
	}
	return append(ret, 0, 0), nil
}
