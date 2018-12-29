package certstore

/*
#cgo CFLAGS: -I/usr/include/nss -I/usr/include/nspr
#cgo LDFLAGS: -lnss3 -lnspr4
#include <nss.h>
#include <pk11pub.h>
#include <nspr.h>
#include <prio.h>
#include <prerror.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

*/
import "C"
import (
	"errors"
	"fmt"
	"syscall"
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
	return []Identity{}, nil
}

func (nssStore) Import(data []byte, password string) error {
	var p12 = C.SECITEM_AllocItem(nil, nil, C.uint(len(data)))
	if p12 == nil {
		return errors.New("SECITEM_AllocItem failed")
	}
	fmt.Printf("p12 : %p\n", p12)
	return nil
}

func (nssStore) Close() {
	//C.NSS_Shutdown()
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
		showCert(C.GoString(node.cert.subjectName))
	}
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
