package certstore

/*
#cgo pkg-config: nss
#include <nss.h>
#include <pk11pub.h>
#include <nspr.h>
#include <prio.h>
#include <prerror.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <p12.h>
#include <p12plcy.h>
#include <stdlib.h>
#include <cryptohi.h>

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
*/
import "C"
import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path"
	"unicode/utf16"
	"unsafe"
)

type nssStore int

func (nssStore) Identities() ([]Identity, error) {
	var identities = make([]Identity, 0)
	//fmt.Printf("Listing certificates:\n")
	var certs = C.PK11_ListCerts(C.PK11CertListAll, nil)
	if certs == nil {
		C.NSS_Shutdown()
		return nil, fmt.Errorf("Error %d, closing and returing...\n", int(C.PR_GetError()))
	}
	var node *C.CERTCertListNode
	for node = C.CertListHead(certs); C.CertListEnd(node, certs) == 0; node = C.CertListNext(node) {
		identity := nssIdentity(*node)
		identities = append(identities, &identity)
	}
	return identities, nil
}

type nssIdentity C.CERTCertListNode

func (i *nssIdentity) Signer() (crypto.Signer, error) {
	return i, nil
}

func (i *nssIdentity) Certificate() (*x509.Certificate, error) {
	var der = i.cert.derCert
	var bytes = C.GoBytes(unsafe.Pointer(der.data), C.int(der.len))
	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (i *nssIdentity) CertificateChain() ([]*x509.Certificate, error) {
	var der = i.cert.derCert
	var bytes = C.GoBytes(unsafe.Pointer(der.data), C.int(der.len))
	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, err
	}
	certs := C.PK11_ListCerts(C.PK11CertListAll, nil)
	if certs == nil {
		return nil, fmt.Errorf("Error %d, cannot list certificates...\n", int(C.PR_GetError()))
	}
	var list *C.CERTCertList
	var node *C.CERTCertListNode
	list = certs
	var identities = make([]Identity, 0)
	var certificates = make([]*x509.Certificate, 0)
	for node = C.CertListHead(list); C.CertListEnd(node, list) == 0; node = C.CertListNext(node) {
		identity := nssIdentity(*node)
		identities = append(identities, &identity)
	}
	certificates = append(certificates, cert)
	found := true
	for found != false {
		found = false
		cert = certificates[len(certificates)-1]
		issuer := cert.Issuer.String()
		for i := 0; i < len(identities); i++ {
			cert, err = identities[i].Certificate()
			if cert == nil {
				return nil, fmt.Errorf("Error %d, cannot fetch certificate...\n", int(C.PR_GetError()))
			}
			subject := cert.Subject.String()
			root := certificates[len(certificates)-1].Subject.String()
			if subject == issuer && subject != root {
				certificates = append(certificates, cert)
				found = true
				break
			}
		}
	}
	return certificates, nil
}

func (i *nssIdentity) Delete() error {
	C.PK11_DeleteTokenCertAndKey(i.cert, nil)
	return nil
}

func (nssIdentity) Close() {
}

func (i *nssIdentity) Public() crypto.PublicKey {
	cert, _ := i.Certificate()
	if cert == nil {
		return nil
	}
	return cert.PublicKey
}

func (i *nssIdentity) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}
	key := C.PK11_FindKeyByAnyCert(i.cert, nil)
	if key == nil {
		return nil, errors.New("cannot find private key")
	}
	if key.keyType == C.rsaKey {
		var pkcs1Prefix = map[crypto.Hash][]byte{
			crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
			crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
			crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
			crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
		}
		oid := pkcs1Prefix[hash]
		if oid == nil {
			return nil, ErrUnsupportedHash
		}
		T := make([]byte, len(oid)+len(digest))
		copy(T[0:len(oid)], oid)
		copy(T[len(oid):], digest)
		digest = T
	}
	sd := C.SECITEM_AllocItem(nil, nil, C.uint(C.PK11_SignatureLen(key)))
	hashed := C.SECITEM_AllocItem(nil, nil, C.uint(len(digest)))
	if hashed == nil {
		return nil, errors.New("SECITEM_AllocItem failed")
	}
	C.memcpy(unsafe.Pointer(hashed.data), unsafe.Pointer(&digest[0]), C.size_t(len(digest)))
	var mechanism C.ulong
	switch key.keyType {
	case C.rsaKey:
		switch hash {
		/*
			case crypto.SHA1:
				mechanism = C.CKM_SHA1_RSA_PKCS
			case crypto.SHA256:
				mechanism = C.CKM_SHA256_RSA_PKCS
			case crypto.SHA384:
				mechanism = C.CKM_SHA384_RSA_PKCS
			case crypto.SHA512:
				mechanism = C.CKM_SHA512_RSA_PKCS
		*/
		default:
			mechanism = C.CKM_RSA_PKCS
		}
	case C.ecKey:
		switch hash {
		/*
			case crypto.SHA1:
				mechanism = C.CKM_ECDSA_SHA1
		*/
		default:
			mechanism = C.CKM_ECDSA
		}
	default:
		return nil, fmt.Errorf("Unknown key type: %d", int(key.keyType))
	}
	ret := C.PK11_SignWithMechanism(key, mechanism, nil, sd, hashed)
	if ret != 0 {
		return nil, errors.New("could not sign")
	}
	var sig = C.GoBytes(unsafe.Pointer(sd.data), C.int(sd.len))
	if key.keyType == C.ecKey {
		if len(sig)%2 != 0 {
			return nil, errors.New("bad ecdsa signature")
		}
		type ecdsaSignature struct {
			R, S *big.Int
		}
		r := new(big.Int).SetBytes(sig[:len(sig)/2])
		s := new(big.Int).SetBytes(sig[len(sig)/2:])
		asn, err := asn1.Marshal(ecdsaSignature{r, s})
		if err != nil {
			return nil, err
		}
		sig = asn
	}
	return sig, nil
}

func (nssStore) Import(data []byte, password string) error {
	unicodePassword, err := bmpString(password)
	if unicodePassword == nil {
		return err
	}
	var pass = C.SECITEM_AllocItem(nil, nil, C.uint(len(unicodePassword)))
	if pass == nil {
		return errors.New("SECITEM_AllocItem failed")
	}
	C.memcpy(unsafe.Pointer(pass.data), unsafe.Pointer(&unicodePassword[0]), C.size_t(len(unicodePassword)))
	var p12 = C.SEC_PKCS12DecoderStart(pass, nil, nil, nil, nil, nil, nil, nil)
	var decoded = C.SEC_PKCS12DecoderUpdate(p12, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if decoded != 0 {
		return fmt.Errorf("Error %d, P12 decoding failed...\n", int(C.PR_GetError()))
	}
	var authenticated = C.SEC_PKCS12DecoderVerify(p12)
	if authenticated != 0 {
		return fmt.Errorf("Error %d, P12 authentication failed...\n", int(C.PR_GetError()))
	}
	var validated = C.SEC_PKCS12DecoderValidateBags(p12, (*[0]byte)(C.P12U_NicknameCollisionCallback))
	if validated != 0 {
		return fmt.Errorf("Error %d, P12 validation failed...\n", int(C.PR_GetError()))
	}
	var imported = C.SEC_PKCS12DecoderImportBags(p12)
	if imported != 0 {
		return fmt.Errorf("Error %d, P12 import failed...\n", int(C.PR_GetError()))
	}
	return nil
}

func (nssStore) Close() {
}

func openStore() (Store, error) {
	homeDir := os.Getenv("HOME")

	if homeDir == "" {
		return nil, errors.New("the HOME environment variable is not defined")
	}

	nssdb := path.Join(homeDir, ".pki", "nssdb")
	if _, err := os.Stat(nssdb); os.IsNotExist(err) {
		return nil, fmt.Errorf("NSS database not found at %s\n", nssdb)
	}
	nssdbURLC := C.CString(fmt.Sprintf("sql:/%s/", nssdb))
	defer C.free(unsafe.Pointer(nssdbURLC))
	ok := C.NSS_InitReadWrite(nssdbURLC)
	if ok != 0 {
		C.NSS_Shutdown()
		return nil, fmt.Errorf("Error %d, closing and returing...\n", int(C.PR_GetError()))
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
