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
	name := fmt.Sprintf("sql:/%s/.pki/nssdb/", passwd.PwDir)
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
	var certs_list = certs.list
	var node = (*C.CERTCertListNode)(*(*unsafe.Pointer)(unsafe.Pointer(&certs_list)))
	var node_links = node.links
	showCert(C.GoString(node.cert.subjectName))
	for ; certs_list != node_links; node_links = *node.links.next {
		node = (*C.CERTCertListNode)(*(*unsafe.Pointer)(unsafe.Pointer(&node_links)))
		showCert(C.GoString(node.cert.subjectName))
	}
	C.NSS_Shutdown()
	return nil, errors.New("Not using NSS yet!\n")
}

func showCert(s string) {
	fmt.Printf("Cetificate: %s\n", s)
}
