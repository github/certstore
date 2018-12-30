package certstore

/*
#cgo CFLAGS: -I/usr/include/nss -I/usr/include/nspr
#cgo LDFLAGS: -lnss3 -lnspr4 -lsmime3
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
	fprintf(stdout, "using nickname: %s\n", nick);
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
*/
import "C"
import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

type Passwd struct {
	PwName   string
	PwPasswd string
	PwUid    int
	PwGid    int
	PwGecos  string
	PwDir    string
	PwShell  string
}
type nssStore int

func (nssStore) Identities() ([]Identity, error) {
	var identities = make([]Identity, 0)
	fmt.Printf("Listing certificaes:\n")
	var certs = C.PK11_ListCerts(C.PK11CertListType(C.PK11CertListAll), unsafe.Pointer(nil))
	if certs == nil {
		C.NSS_Shutdown()
		return nil, errors.New(fmt.Sprintf("Error %d, closing and returing...\n", int(C.PR_GetError())))
	}
	var list *C.CERTCertList
	var node *C.CERTCertListNode
	list = certs
	for node = CertListHead(list); ! CertListEnd(node, list); node = CertListNext(node) {
		identities = append(identities, newNssIdentity(node))
		showCert(C.GoString(node.cert.subjectName))
	}
	return identities, nil
}

type nssIdentity struct {
	node *C.CERTCertListNode
}

type nssPrivateKey struct {
	node *C.CERTCertListNode
}

func (i *nssIdentity) Signer() (crypto.Signer, error) {
	return i.newNssPrivateKey()
}

func (i *nssIdentity) Certificate() (*x509.Certificate, error) {
	var der = i.node.cert.derCert
	var bytes = C.GoBytes(unsafe.Pointer(der.data), C.int(der.len))
	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (nssIdentity) CertificateChain() ([]*x509.Certificate, error) {
	return nil, nil
}

func (nssIdentity) Delete() error {
	return nil
}

func (nssIdentity) Close() {
}

func (i *nssIdentity) newNssPrivateKey() (*nssPrivateKey, error) {
	return &nssPrivateKey{node: i.node}, nil
}

func (i *nssPrivateKey) Public() crypto.PublicKey {
	var der = i.node.cert.derCert
	var bytes = C.GoBytes(unsafe.Pointer(der.data), C.int(der.len))
	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil
	}
	return cert.PublicKey
}

func (i *nssPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}
	privKey := C.PK11_FindKeyByAnyCert(i.node.cert, nil);
	if privKey == nil {
		return nil, errors.New("cannot find private key")
	}
	algId := C.SEC_GetSignatureAlgorithmOidTag(privKey.keyType, C.CKM_RSA_PKCS)
	if algId == 0 {
		return nil, errors.New("cannot find algo")
	}
	sd := &C.SECItem{}
	fmt.Printf("%p:\n", unsafe.Pointer(sd))
	ret := C.SEC_SignData(sd, (*C.uchar)(unsafe.Pointer(&digest[0])), C.int(len(digest)), privKey, algId);
	if ret != 0 {
		return nil, errors.New("could not sign")
	}
	var sig = C.GoBytes(unsafe.Pointer(sd.data), C.int(sd.len))
	return sig, nil
}

func newNssIdentity(node *C.CERTCertListNode) *nssIdentity {
	return &nssIdentity{node: node}
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
		return errors.New(fmt.Sprintf("Error %d, P12 decoding failed...\n", int(C.PR_GetError())))
	}
	var authenticated = C.SEC_PKCS12DecoderVerify(p12)
	if authenticated != 0 {
		return errors.New(fmt.Sprintf("Error %d, P12 authentication failed...\n", int(C.PR_GetError())))
	}
	var validated = C.SEC_PKCS12DecoderValidateBags(p12, (*[0]byte)(C.P12U_NicknameCollisionCallback))
	if validated != 0 {
		return errors.New(fmt.Sprintf("Error %d, P12 validation failed...\n", int(C.PR_GetError())))
	}
	var imported = C.SEC_PKCS12DecoderImportBags(p12)
	if imported != 0 {
		return errors.New(fmt.Sprintf("Error %d, P12 import failed...\n", int(C.PR_GetError())))
	}
	return nil
}

func (nssStore) Close() {
}

func openStore() (Store, error) {
	var passwd *Passwd = nil
	passwdC, err := C.getpwuid(C.getuid())
	if passwdC == nil {
		if err == nil {
			var e syscall.Errno
			err = errors.New(e.Error())
		}
		return nil, errors.New(fmt.Sprintf("There was an error (%s) when getting user info\n", error(err)))
	} else {
		passwd = &Passwd{
			PwName:   C.GoString(passwdC.pw_name),
			PwPasswd: C.GoString(passwdC.pw_passwd),
			PwUid:    int(passwdC.pw_uid),
			PwGid:    int(passwdC.pw_gid),
			PwGecos:  C.GoString(passwdC.pw_gecos),
			PwDir:    C.GoString(passwdC.pw_dir),
			PwShell:  C.GoString(passwdC.pw_shell),
		}
		fmt.Printf("Home directory is: %s\n", passwd.PwDir)
	}
	if passwd == nil {
		return nil, errors.New("Cannot locate nssdb store!\n")
	}
	name := fmt.Sprintf("sql:/%s/.pki-test/nssdb/", passwd.PwDir)
	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))
	fmt.Printf("Opening: %s\n", name)
	nss := C.NSS_InitReadWrite(nameC)
	if nss != 0 {
		C.NSS_Shutdown()
		return nil, errors.New(fmt.Sprintf("Error %d, closing and returing...\n", int(C.PR_GetError())))
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

func showCert(s string) {
	fmt.Printf("Cetificate: %s\n", s)
}

func CertListHead(l *C.CERTCertList) *C.CERTCertListNode {
	var list = l.list
	return (*C.CERTCertListNode)(*(*unsafe.Pointer)(unsafe.Pointer(&list)))
}

func CertListNext(n *C.CERTCertListNode) *C.CERTCertListNode {
	var list = n.links
	return (*C.CERTCertListNode)(*(*unsafe.Pointer)(unsafe.Pointer(&list)))
}

func CertListEnd(n *C.CERTCertListNode, l *C.CERTCertList) bool {
	var list = l.list
	return *(*unsafe.Pointer)(unsafe.Pointer(n)) == *(*unsafe.Pointer)(unsafe.Pointer(&list))
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
