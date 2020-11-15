// +build windows

package certstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/pkg/errors"
)

var (
	crypt32  = windows.MustLoadDLL("crypt32.dll")
	ncrypt   = windows.MustLoadDLL("ncrypt.dll")
	advapi32 = windows.MustLoadDLL("advapi32.dll")

	certDuplicateCertificateContext   = crypt32.MustFindProc("CertDuplicateCertificateContext")
	certDeleteCertificateFromStore    = crypt32.MustFindProc("CertDeleteCertificateFromStore")
	certFindCertificateInStore        = crypt32.MustFindProc("CertFindCertificateInStore")
	certFindChainInStore              = crypt32.MustFindProc("CertFindChainInStore")
	certFreeCertificateContext        = crypt32.MustFindProc("CertFreeCertificateContext")
	cryptAcquireCertificatePrivateKey = crypt32.MustFindProc("CryptAcquireCertificatePrivateKey")

	cryptReleaseContext = advapi32.MustFindProc("CryptReleaseContext")

	nCryptSignHash   = ncrypt.MustFindProc("NCryptSignHash")
	nCryptFreeObject = ncrypt.MustFindProc("NCryptFreeObject")
)

const (
	certStoreProvSystem                   = 10                                                              // CERT_STORE_PROV_SYSTEM
	certStoreCurrentUserID                = 1                                                               // CERT_SYSTEM_STORE_CURRENT_USER_ID
	certStoreLocalMachineID               = 2                                                               // CERT_SYSTEM_STORE_LOCAL_MACHINE_ID
	certSystemStoreLocationShift          = 16                                                              // CERT_SYSTEM_STORE_LOCATION_SHIFT
	certStoreCurrentUser                  = uint32(certStoreCurrentUserID << certSystemStoreLocationShift)  // CERT_SYSTEM_STORE_CURRENT_USER
	certStoreLocalMachine                 = uint32(certStoreLocalMachineID << certSystemStoreLocationShift) // CERT_SYSTEM_STORE_LOCAL_MACHINE
	x509AsnEncoding                       = 1                                                               // X509_ASN_ENCODING
	certChainFindByIssuerCacheOnlyFlag    = 0x8000                                                          // CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG
	certChainFindByIssuerCacheOnlyUrlFlag = 0x0004                                                          // CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG
	certChainFindByIssuer                 = 1                                                               // CERT_CHAIN_FIND_BY_ISSUER
	cryptAcquireCacheFlag                 = 0x1                                                             // CRYPT_ACQUIRE_CACHE_FLAG
	cryptAcquireSilentFlag                = 0x40                                                            // CRYPT_ACQUIRE_SILENT_FLAG
	cryptAcquireOnlyNcryptKeyFlag         = 0x40000                                                         // CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG
	bcryptPadPkcs1                        = 0x00000002                                                      // BCRYPT_PAD_PKCS1
	bcryptPadPss                          = 0x00000008                                                      // BCRYPT_PAD_PSS
	cryptENotFound                        = 0x80092004                                                      // CRYPT_E_NOT_FOUND
	certNcryptKeySpec                     = 0xFFFFFFFF                                                      // CERT_NCRYPT_KEY_SPEC
)

// winStore is a wrapper around a C.HCERTSTORE.
type winStore struct {
	store windows.Handle
}

// openStore opens the current user's personal cert store.
func openStore() (Store, error) {
	return OpenStoreWindows("MY", StoreLocationCurrentUser)
}

type StoreLocation int

const (
	StoreLocationCurrentUser = iota
	StoreLocationLocalMachine
)

func OpenStoreWindows(store string, location StoreLocation) (Store, error) {
	storeName, err := windows.UTF16PtrFromString(store)
	if err != nil {
		return nil, err
	}

	loc := certStoreCurrentUser

	if location == StoreLocationLocalMachine {
		loc = certStoreLocalMachine
	}

	h, err := windows.CertOpenStore(certStoreProvSystem, 0, 0, loc, uintptr(unsafe.Pointer(storeName)))
	if err != nil {
		return nil, err
	}

	return &winStore{h}, nil
}

type certChainFindByIssuerPara struct {
	Size                   uint32
	UsageIdentifier        *byte
	KeySpec                uint32
	AcquirePrivateKeyFlags uint32
	IssuerCount            uint32
	Issuer                 windows.Pointer
	FindCallback           windows.Pointer
	FindArg                windows.Pointer
}

// Identities implements the Store interface.
func (s *winStore) Identities() ([]Identity, error) {
	var (
		err    error
		idents = []Identity{}

		encoding = uintptr(x509AsnEncoding)
		flags    = uintptr(certChainFindByIssuerCacheOnlyFlag | certChainFindByIssuerCacheOnlyUrlFlag)
		findType = uintptr(certChainFindByIssuer)
	)
	var params certChainFindByIssuerPara
	params.Size = uint32(unsafe.Sizeof(params))
	var paramsPtr = uintptr(unsafe.Pointer(&params))

	var chainCtx *windows.CertChainContext

	for {
		h, _, _ := certFindChainInStore.Call(uintptr(s.store), encoding, flags, findType, paramsPtr, uintptr(unsafe.Pointer(chainCtx)))

		if h == 0 {
			break
		}

		chainCtx = (*windows.CertChainContext)(unsafe.Pointer(h))

		if chainCtx.ChainCount < 1 {
			err = errors.New("bad chain")
			goto fail
		}

		// not sure why this isn't 1 << 29
		const maxPointerArray = 1 << 28

		// rgpChain is actually an array, but we only care about the first one.
		simpleChain := *chainCtx.Chains
		if simpleChain.NumElements < 1 || simpleChain.NumElements > maxPointerArray {
			err = errors.New("bad chain")
			goto fail
		}

		var chainElts []*windows.CertChainElement
		slice := (*reflect.SliceHeader)(unsafe.Pointer(&chainElts))
		slice.Data = uintptr(unsafe.Pointer(simpleChain.Elements))
		slice.Len = int(simpleChain.NumElements)
		slice.Cap = int(simpleChain.NumElements)

		chain := make([]*windows.CertContext, simpleChain.NumElements)

		for j := range chainElts {
			chain[j] = chainElts[j].CertContext
		}

		idents = append(idents, newWinIdentity(chain))
	}

	if errno, ok := err.(syscall.Errno); ok && errno == cryptENotFound {
		goto fail
	}

	return idents, nil

fail:
	for _, ident := range idents {
		ident.Close()
	}

	return nil, err
}

// Import implements the Store interface.
func (s *winStore) Import(data []byte, password string) error {
	// cdata := C.CBytes(data)
	// defer C.free(cdata)

	// cpw := stringToUTF16(password)
	// defer C.free(unsafe.Pointer(cpw))

	// pfx := &C.CRYPT_DATA_BLOB{
	// 	cbData: C.DWORD(len(data)),
	// 	pbData: (*C.BYTE)(cdata),
	// }

	// flags := C.CRYPT_USER_KEYSET

	// // import into preferred KSP
	// if winAPIFlag&C.CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG > 0 {
	// 	flags |= C.PKCS12_PREFER_CNG_KSP
	// } else if winAPIFlag&C.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG > 0 {
	// 	flags |= C.PKCS12_ALWAYS_CNG_KSP
	// }

	// store := C.PFXImportCertStore(pfx, cpw, C.DWORD(flags))
	// if store == nil {
	// 	return lastError("failed to import PFX cert store")
	// }
	// defer C.CertCloseStore(store, C.CERT_CLOSE_STORE_FORCE_FLAG)

	// var (
	// 	ctx      = C.PCCERT_CONTEXT(nil)
	// 	encoding = C.DWORD(C.X509_ASN_ENCODING | C.PKCS_7_ASN_ENCODING)
	// )

	// for {
	// 	// iterate through certs in temporary store
	// 	if ctx = C.CertFindCertificateInStore(store, encoding, 0, C.CERT_FIND_ANY, nil, ctx); ctx == nil {
	// 		if err := checkError("failed to iterate certs in store"); err != nil && errors.Cause(err) != errCode(CRYPT_E_NOT_FOUND) {
	// 			return err
	// 		}

	// 		break
	// 	}

	// 	// Copy the cert to the system store.
	// 	if ok := C.CertAddCertificateContextToStore(s.store, ctx, C.CERT_STORE_ADD_REPLACE_EXISTING, nil); ok == winFalse {
	// 		return lastError("failed to add importerd certificate to MY store")
	// 	}
	// }

	return nil
}

// Close implements the Store interface.
func (s *winStore) Close() {
	windows.CertCloseStore(s.store, 0)
}

// winIdentity implements the Identity interface.
type winIdentity struct {
	chain  []*windows.CertContext
	signer *winPrivateKey
}

func newWinIdentity(chain []*windows.CertContext) *winIdentity {
	for _, ctx := range chain {
		certDuplicateCertificateContext.Call(uintptr(unsafe.Pointer(ctx)))
	}

	return &winIdentity{chain: chain}
}

// Certificate implements the Identity interface.
func (i *winIdentity) Certificate() (*x509.Certificate, error) {
	return exportCertCtx(i.chain[0])
}

// CertificateChain implements the Identity interface.
func (i *winIdentity) CertificateChain() ([]*x509.Certificate, error) {
	var (
		certs = make([]*x509.Certificate, len(i.chain))
		err   error
	)

	for j := range i.chain {
		if certs[j], err = exportCertCtx(i.chain[j]); err != nil {
			return nil, err
		}
	}

	return certs, nil
}

// Signer implements the Identity interface.
func (i *winIdentity) Signer() (crypto.Signer, error) {
	return i.getPrivateKey()
}

// getPrivateKey gets this identity's private *winPrivateKey.
func (i *winIdentity) getPrivateKey() (*winPrivateKey, error) {
	if i.signer != nil {
		return i.signer, nil
	}

	cert, err := i.Certificate()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get identity certificate")
	}

	signer, err := newWinPrivateKey(i.chain[0], cert.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load identity private key")
	}

	i.signer = signer

	return i.signer, nil
}

// Delete implements the Identity interface.
func (i *winIdentity) Delete() error {
	// duplicate cert context, since CertDeleteCertificateFromStore will free it.
	deleteCtx, _, err := certDuplicateCertificateContext.Call(uintptr(unsafe.Pointer(i.chain[0])))
	if deleteCtx == 0 {
		return err
	}

	r, _, err := certDeleteCertificateFromStore.Call(deleteCtx)
	if r == 0 {
		return err
	}

	// try deleting private key
	wpk, err := i.getPrivateKey()
	if err != nil {
		return errors.Wrap(err, "failed to get identity private key")
	}

	if err := wpk.Delete(); err != nil {
		return errors.Wrap(err, "failed to delete identity private key")
	}

	return nil
}

// Close implements the Identity interface.
func (i *winIdentity) Close() {
	if i.signer != nil {
		i.signer.Close()
		i.signer = nil
	}

	for _, ctx := range i.chain {
		certFreeCertificateContext.Call(uintptr(unsafe.Pointer(ctx)))
		i.chain = nil
	}
}

// winPrivateKey is a wrapper around a HCRYPTPROV_OR_NCRYPT_KEY_HANDLE.
type winPrivateKey struct {
	publicKey crypto.PublicKey

	// CryptoAPI fields
	capiProv uintptr

	// CNG fields
	cngHandle uintptr
	keySpec   uint32
}

// newWinPrivateKey gets a *winPrivateKey for the given certificate.
func newWinPrivateKey(certCtx *windows.CertContext, publicKey crypto.PublicKey) (*winPrivateKey, error) {
	if publicKey == nil {
		return nil, errors.New("nil public key")
	}

	var (
		h        uintptr
		keySpec  uint32
		mustFree int
	)
	r, _, err := cryptAcquireCertificatePrivateKey.Call(
		uintptr(unsafe.Pointer(certCtx)),
		cryptAcquireCacheFlag|cryptAcquireSilentFlag|cryptAcquireOnlyNcryptKeyFlag,
		0, // Reserved, must be null.
		uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(&keySpec)),
		uintptr(unsafe.Pointer(&mustFree)),
	)

	if r == 0 {
		return nil, err
	}

	if mustFree != 0 {
		// This shouldn't happen since we're not asking for cached keys.
		return nil, errors.New("CryptAcquireCertificatePrivateKey set mustFree")
	}

	if keySpec == certNcryptKeySpec {
		return &winPrivateKey{
			publicKey: publicKey,
			cngHandle: h,
		}, nil
	} else {
		return &winPrivateKey{
			publicKey: publicKey,
			capiProv:  h,
			keySpec:   keySpec,
		}, nil
	}
}

// Public implements the crypto.Signer interface.
func (wpk *winPrivateKey) Public() crypto.PublicKey {
	return wpk.publicKey
}

// Sign implements the crypto.Signer interface.
func (wpk *winPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if wpk.cngHandle != 0 {
		return wpk.cngSignHash(opts, digest)
	} else if wpk.capiProv != 0 {
		panic("capi")
		// return wpk.capiSignHash(opts.HashFunc(), digest)
	} else {
		return nil, errors.New("bad private key")
	}
}

type bcryptPkcs1PaddingInfo struct {
	pszAlgID *uint16
}

type bcryptPssPaddingInfo struct {
	pszAlgID *uint16
	cbSalt   uint64
}

// cngSignHash signs a digest using the CNG APIs.
func (wpk *winPrivateKey) cngSignHash(opts crypto.SignerOpts, digest []byte) ([]byte, error) {
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, errors.New("bad digest for hash")
	}

	var (
		// input
		padPtr    = uintptr(unsafe.Pointer(nil))
		digestPtr = uintptr(unsafe.Pointer((&digest[0])))
		digestLen = uintptr(len(digest))
		flags     = uintptr(0)

		// output
		sigLen = uint32(0)
	)

	// setup pkcs1v1.5 padding for RSA
	if _, isRSA := wpk.publicKey.(*rsa.PublicKey); isRSA {
		var pszAlgId *uint16

		switch hash {
		case crypto.SHA1:
			pszAlgId = windows.StringToUTF16Ptr("SHA1")
		case crypto.SHA256:
			pszAlgId = windows.StringToUTF16Ptr("SHA256")
		case crypto.SHA384:
			pszAlgId = windows.StringToUTF16Ptr("SHA384")
		case crypto.SHA512:
			pszAlgId = windows.StringToUTF16Ptr("SHA512")
		default:
			return nil, ErrUnsupportedHash
		}

		if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
			saltLength := pssOpts.SaltLength
			switch saltLength {
			case rsa.PSSSaltLengthAuto:
				// TODO priv property
				// saltLength = priv.Size() - 2 - hash.Size()
				return nil, ErrUnsupportedHash
			case rsa.PSSSaltLengthEqualsHash:
				saltLength = hash.Size()
			}

			flags = bcryptPadPss
			padPtr = uintptr(unsafe.Pointer(&bcryptPssPaddingInfo{
				pszAlgID: pszAlgId,
				cbSalt:   uint64(saltLength),
			}))

		} else {
			flags = bcryptPadPkcs1
			padPtr = uintptr(unsafe.Pointer(&bcryptPkcs1PaddingInfo{
				pszAlgID: pszAlgId,
			}))
		}
	}

	r, _, err := nCryptSignHash.Call(
		wpk.cngHandle,
		padPtr,
		digestPtr,
		digestLen,
		0,
		0,
		uintptr(unsafe.Pointer(&sigLen)),
		flags)

	if r != 0 {
		return nil, errors.Wrap(err, "failed to get signature length")
	}

	// get signature
	sig := make([]byte, sigLen)
	sigPtr := uintptr(unsafe.Pointer(&sig[0]))

	r, _, err = nCryptSignHash.Call(
		wpk.cngHandle,
		padPtr,
		digestPtr,
		digestLen,
		sigPtr,
		uintptr(sigLen),
		uintptr(unsafe.Pointer(&sigLen)),
		flags)

	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash returned %X during signing: %v", r, err)
	}

	// CNG returns a raw ECDSA signature, but we wan't ASN.1 DER encoding.
	if _, isEC := wpk.publicKey.(*ecdsa.PublicKey); isEC {
		if len(sig)%2 != 0 {
			return nil, errors.New("bad ecdsa signature from CNG")
		}

		type ecdsaSignature struct {
			R, S *big.Int
		}

		r := new(big.Int).SetBytes(sig[:len(sig)/2])
		s := new(big.Int).SetBytes(sig[len(sig)/2:])

		encoded, err := asn1.Marshal(ecdsaSignature{r, s})
		if err != nil {
			return nil, errors.Wrap(err, "failed to ASN.1 encode EC signature")
		}

		return encoded, nil
	}

	return sig[:sigLen], nil
}

// capiSignHash signs a digest using the CryptoAPI APIs.
func (wpk *winPrivateKey) capiSignHash(hash crypto.Hash, digest []byte) ([]byte, error) {
	// if len(digest) != hash.Size() {
	// 	return nil, errors.New("bad digest for hash")
	// }

	// // // Figure out which CryptoAPI hash algorithm we're using.
	// var hash_alg uint32

	// switch hash {
	// case crypto.SHA1:
	// 	hash_alg = C.CALG_SHA1
	// case crypto.SHA256:
	// 	hash_alg = C.CALG_SHA_256
	// case crypto.SHA384:
	// 	hash_alg = C.CALG_SHA_384
	// case crypto.SHA512:
	// 	hash_alg = C.CALG_SHA_512
	// default:
	// 	return nil, ErrUnsupportedHash
	// }

	// // Instantiate a CryptoAPI hash object.
	// var chash C.HCRYPTHASH

	// if ok := C.CryptCreateHash(C.HCRYPTPROV(wpk.capiProv), hash_alg, 0, 0, &chash); ok == winFalse {
	// 	if err := lastError("failed to create hash"); errors.Cause(err) == errCode(NTE_BAD_ALGID) {
	// 		return nil, ErrUnsupportedHash
	// 	} else {
	// 		return nil, err
	// 	}
	// }
	// defer C.CryptDestroyHash(chash)

	// // Make sure the hash size matches.
	// var (
	// 	hashSize    C.DWORD
	// 	hashSizePtr = (*C.BYTE)(unsafe.Pointer(&hashSize))
	// 	hashSizeLen = C.DWORD(unsafe.Sizeof(hashSize))
	// )

	// if ok := C.CryptGetHashParam(chash, C.HP_HASHSIZE, hashSizePtr, &hashSizeLen, 0); ok == winFalse {
	// 	return nil, lastError("failed to get hash size")
	// }

	// if hash.Size() != int(hashSize) {
	// 	return nil, errors.New("invalid CryptoAPI hash")
	// }

	// // Put our digest into the hash object.
	// digestPtr := (*C.BYTE)(unsafe.Pointer(&digest[0]))
	// if ok := C.CryptSetHashParam(chash, C.HP_HASHVAL, digestPtr, 0); ok == winFalse {
	// 	return nil, lastError("failed to set hash digest")
	// }

	// // Get signature length.
	// var sigLen C.DWORD

	// if ok := C.CryptSignHash(chash, wpk.keySpec, nil, 0, nil, &sigLen); ok == winFalse {
	// 	return nil, lastError("failed to get signature length")
	// }

	// // Get signature
	// var (
	// 	sig    = make([]byte, int(sigLen))
	// 	sigPtr = (*C.BYTE)(unsafe.Pointer(&sig[0]))
	// )

	// if ok := C.CryptSignHash(chash, wpk.keySpec, nil, 0, sigPtr, &sigLen); ok == winFalse {
	// 	return nil, lastError("failed to sign digest")
	// }

	// // Signature is little endian, but we want big endian. Reverse it.
	// for i := len(sig)/2 - 1; i >= 0; i-- {
	// 	opp := len(sig) - 1 - i
	// 	sig[i], sig[opp] = sig[opp], sig[i]
	// }

	// return sig, nil
	panic("not impl")
}

func (wpk *winPrivateKey) Delete() error {
	// if wpk.cngHandle != 0 {
	// 	// Delete CNG key
	// 	if err := checkStatus(C.NCryptDeleteKey(wpk.cngHandle, 0)); err != nil {
	// 		return err
	// 	}
	// } else if wpk.capiProv != 0 {
	// 	// Delete CryptoAPI key
	// 	var (
	// 		param unsafe.Pointer
	// 		err   error

	// 		containerName C.LPCTSTR
	// 		providerName  C.LPCTSTR
	// 		providerType  *C.DWORD
	// 	)

	// 	if param, err = wpk.getProviderParam(C.PP_CONTAINER); err != nil {
	// 		return errors.Wrap(err, "failed to get PP_CONTAINER")
	// 	} else {
	// 		containerName = C.LPCTSTR(param)
	// 	}

	// 	if param, err = wpk.getProviderParam(C.PP_NAME); err != nil {
	// 		return errors.Wrap(err, "failed to get PP_NAME")
	// 	} else {
	// 		providerName = C.LPCTSTR(param)
	// 	}

	// 	if param, err = wpk.getProviderParam(C.PP_PROVTYPE); err != nil {
	// 		return errors.Wrap(err, "failed to get PP_PROVTYPE")
	// 	} else {
	// 		providerType = (*C.DWORD)(param)
	// 	}

	// 	// use CRYPT_SILENT too?
	// 	var prov C.HCRYPTPROV
	// 	if ok := C.CryptAcquireContext(&prov, containerName, providerName, *providerType, C.CRYPT_DELETEKEYSET); ok == winFalse {
	// 		return lastError("failed to delete key set")
	// 	}
	// } else {
	// 	return errors.New("bad private key")
	// }

	return nil
}

// getProviderParam gets a parameter about a provider.
// func (wpk *winPrivateKey) getProviderParam(param C.DWORD) (unsafe.Pointer, error) {
// 	var dataLen C.DWORD
// 	if ok := C.CryptGetProvParam(wpk.capiProv, param, nil, &dataLen, 0); ok == winFalse {
// 		return nil, lastError("failed to get provider parameter size")
// 	}

// 	data := make([]byte, dataLen)
// 	dataPtr := (*C.BYTE)(unsafe.Pointer(&data[0]))
// 	if ok := C.CryptGetProvParam(wpk.capiProv, param, dataPtr, &dataLen, 0); ok == winFalse {
// 		return nil, lastError("failed to get provider parameter")
// 	}

// 	// TODO leaking memory here
// 	return C.CBytes(data), nil
// }

// Close closes this winPrivateKey.
func (wpk *winPrivateKey) Close() {
	if wpk.cngHandle != 0 {
		nCryptFreeObject.Call(wpk.cngHandle)
		wpk.cngHandle = 0
	}

	if wpk.capiProv != 0 {
		cryptReleaseContext.Call(wpk.capiProv, 0)
		wpk.capiProv = 0
	}
}

// exportCertCtx exports a windows.CertContext as an *x509.Certificate.
func exportCertCtx(ctx *windows.CertContext) (*x509.Certificate, error) {
	var der []byte
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&der))
	slice.Data = uintptr(unsafe.Pointer(ctx.EncodedCert))
	slice.Len = int(ctx.Length)
	slice.Cap = int(ctx.Length)
	return x509.ParseCertificate(der)
}
