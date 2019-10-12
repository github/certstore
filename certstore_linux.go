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
		fprintf(stdout, "cancel: %p, cert: %p\n", cancel, cert);
		return NULL;
	}
	nick = CERT_MakeCANickname(cert);
	if (!nick) {
		fprintf(stdout, "nick %p\n", nick);
		return NULL;
	}
	if (old_nick && old_nick->data && old_nick->len &&
		PORT_Strlen(nick) == old_nick->len &&
		!PORT_Strncmp((char *)old_nick->data, nick, old_nick->len)) {
		PORT_Free(nick);
		fprintf(stdout, "old_nick %p, nick %p\n", old_nick, nick);
		return NULL;
    }
	//fprintf(stdout, "using nickname: %s\n", nick);
	ret_nick = PORT_ZNew(SECItem);
	if (ret_nick == NULL) {
		PORT_Free(nick);
		fprintf(stdout, "ret_nick %p\n", ret_nick);
		return NULL;
	}
	ret_nick->data = (unsigned char *)nick;
	ret_nick->len = PORT_Strlen(nick);
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

// nssStore is a bogus type. We have to explicitly open/close the store on
// windows, so we provide those methods here too.
type nssStore int

// Identities implements the Store interface.
func (nssStore) Identities() ([]Identity, error) {
	var (
		identities = make([]Identity, 0)
		certs      = C.PK11_ListCerts(C.PK11CertListUser, nil)
		node       *C.CERTCertListNode
	)
	if certs == nil {
		C.NSS_Shutdown()
		return nil, fmt.Errorf("error %d, closing and returing", int(C.PR_GetError()))
	}
	defer C.CERT_DestroyCertList(certs)
	for node = C.CertListHead(certs); C.CertListEnd(node, certs) == 0; node = C.CertListNext(node) {
		identity := nssIdentity(*C.CERT_DupCertificate(node.cert))
		identities = append(identities, &identity)
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
	var (
		cert  = C.CERTCertificate(*i)
		certs = C.CERT_GetCertChainFromCert(&cert, C.PR_Now(), C.certUsageAnyCA)
	)
	if certs == nil {
		return nil, fmt.Errorf("error building certificate chain: %s", C.GoString(C.GetErrorString()))
	}
	defer C.CERT_DestroyCertList(certs)

	var (
		certificates = make([]*x509.Certificate, 0)
		node         *C.CERTCertListNode
	)
	for node = C.CertListHead(certs); C.CertListEnd(node, certs) == 0; node = C.CertListNext(node) {
		var (
			identity  = nssIdentity(*node.cert)
			cert, err = identity.Certificate()
		)
		if err != nil {
			return nil, errors.New("unable to parse certificate when building chain")
		}
		certificates = append(certificates, cert)
	}
	return certificates, nil
}

// Delete implements the Identity interface.
func (i *nssIdentity) Delete() error {
	var (
		cert      = C.CERTCertificate(*i)
		secstatus = C.PK11_DeleteTokenCertAndKey(&cert, nil)
	)
	if secstatus != C.SECSuccess {
		return errors.New("failed to delete certificate & key pair")
	}
	return nil
}

// Close implements the Identity interface.
func (i *nssIdentity) Close() {
	cert := C.CERTCertificate(*i)
	C.CERT_DestroyCertificate(&cert)
}

// Public implements the crypto.Signer interface.
func (i *nssIdentity) Public() crypto.PublicKey {
	var cert, _ = i.Certificate()
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
	var (
		cert = C.CERTCertificate(*i)
		key  = C.PK11_FindKeyByAnyCert(&cert, nil)
	)
	if key == nil {
		return nil, errors.New("cannot find private key")
	}

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
		return nil, fmt.Errorf("error signing: %s\n", C.GoString(C.GetErrorString()))
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
		return errors.New("SECITEM_AllocItem failed")
	}
	C.memcpy(unsafe.Pointer(pass.data), unsafe.Pointer(&unicodePassword[0]), C.size_t(len(unicodePassword)))
	var (
		p12     = C.SEC_PKCS12DecoderStart(pass, nil, nil, nil, nil, nil, nil, nil)
		decoded = C.SEC_PKCS12DecoderUpdate(p12, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	)
	if decoded != 0 {
		return fmt.Errorf("error %d, P12 decoding failed", int(C.PR_GetError()))
	}
	authenticated := C.SEC_PKCS12DecoderVerify(p12)
	if authenticated != 0 {
		return fmt.Errorf("error %d, P12 authentication failed", int(C.PR_GetError()))
	}
	validated := C.SEC_PKCS12DecoderValidateBags(p12, (*[0]byte)(C.P12U_NicknameCollisionCallback))
	if validated != 0 {
		return fmt.Errorf("error %d, P12 validation failed", int(C.PR_GetError()))
	}
	imported := C.SEC_PKCS12DecoderImportBags(p12)
	if imported != 0 {
		return fmt.Errorf("error %d, P12 import failed", int(C.PR_GetError()))
	}
	return nil
}

// Close implements the Store interface.
func (nssStore) Close() {
}

// openStore opens the current user's NSS database.
func openStore() (Store, error) {
	homeDir, err := os.UserHomeDir()

	if err != nil {
		return nil, err
	}

	nssdb := path.Join(homeDir, ".pki", "nssdb")
	if _, err := os.Stat(nssdb); os.IsNotExist(err) {
		return nil, fmt.Errorf("NSS database not found at %s", nssdb)
	}
	nssdbURLC := C.CString(fmt.Sprintf("sql:/%s/", nssdb))
	defer C.free(unsafe.Pointer(nssdbURLC))
	ok := C.NSS_InitReadWrite(nssdbURLC)
	if ok != 0 {
		C.NSS_Shutdown()
		return nil, fmt.Errorf("error %d, closing and returing", int(C.PR_GetError()))
	}
	C.SEC_PKCS12EnableCipher(C.PKCS12_RC4_40, 1)
	C.SEC_PKCS12EnableCipher(C.PKCS12_RC4_128, 1)
	C.SEC_PKCS12EnableCipher(C.PKCS12_RC2_CBC_40, 1)
	C.SEC_PKCS12EnableCipher(C.PKCS12_RC2_CBC_128, 1)
	C.SEC_PKCS12EnableCipher(C.PKCS12_DES_56, 1)
	C.SEC_PKCS12EnableCipher(C.PKCS12_DES_EDE3_168, 1)
	C.SEC_PKCS12EnableCipher(C.PKCS12_AES_CBC_128, 1)
	C.SEC_PKCS12EnableCipher(C.PKCS12_AES_CBC_192, 1)
	C.SEC_PKCS12EnableCipher(C.PKCS12_AES_CBC_256, 1)
	C.SEC_PKCS12SetPreferredCipher(C.PKCS12_DES_EDE3_168, 1)
	return nssStore(0), nil
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
