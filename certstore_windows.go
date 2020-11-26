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
	crypt32 = windows.MustLoadDLL("crypt32.dll")
	ncrypt  = windows.MustLoadDLL("ncrypt.dll")

	certDuplicateCertificateContext   = crypt32.MustFindProc("CertDuplicateCertificateContext")
	certDeleteCertificateFromStore    = crypt32.MustFindProc("CertDeleteCertificateFromStore")
	certFindCertificateInStore        = crypt32.MustFindProc("CertFindCertificateInStore")
	certFindChainInStore              = crypt32.MustFindProc("CertFindChainInStore")
	certFreeCertificateContext        = crypt32.MustFindProc("CertFreeCertificateContext")
	cryptAcquireCertificatePrivateKey = crypt32.MustFindProc("CryptAcquireCertificatePrivateKey")
	pfxImportCertStore                = crypt32.MustFindProc("PFXImportCertStore")
	certCloseStore                    = crypt32.MustFindProc("CertCloseStore")
	certAddCertificateContextToStore  = crypt32.MustFindProc("CertAddCertificateContextToStore")

	nCryptSignHash   = ncrypt.MustFindProc("NCryptSignHash")
	nCryptFreeObject = ncrypt.MustFindProc("NCryptFreeObject")
	nCryptDeleteKey  = ncrypt.MustFindProc("NCryptDeleteKey")
)

const (
	certChainFindByIssuerCacheOnlyFlag    = 0x8000                             // CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_FLAG
	certChainFindByIssuerCacheOnlyURLFlag = 0x0004                             // CERT_CHAIN_FIND_BY_ISSUER_CACHE_ONLY_URL_FLAG
	certChainFindByIssuer                 = 1                                  // CERT_CHAIN_FIND_BY_ISSUER
	cryptAcquireCacheFlag                 = 0x1                                // CRYPT_ACQUIRE_CACHE_FLAG
	cryptAcquireSilentFlag                = 0x40                               // CRYPT_ACQUIRE_SILENT_FLAG
	cryptAcquireOnlyNcryptKeyFlag         = 0x40000                            // CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG
	bcryptPadPkcs1                        = 0x00000002                         // BCRYPT_PAD_PKCS1
	bcryptPadPss                          = 0x00000008                         // BCRYPT_PAD_PSS
	certNcryptKeySpec                     = 0xFFFFFFFF                         // CERT_NCRYPT_KEY_SPEC
	cryptUserKeyset                       = 0x00001000                         // CRYPT_USER_KEYSET
	pkcs12AlwaysCngKsp                    = 0x00000200                         // PKCS12_ALWAYS_CNG_KSP
	certCloseStoreForceFlag               = 0x00000001                         // CERT_CLOSE_STORE_FORCE_FLAG
	certCompareAny                        = 0                                  // CERT_COMPARE_ANY
	certCompareShift                      = 16                                 // CERT_COMPARE_SHIFT
	certFindAny                           = certCompareAny << certCompareShift // CERT_FIND_ANY
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

	var loc uint32 = windows.CERT_SYSTEM_STORE_CURRENT_USER

	if location == StoreLocationLocalMachine {
		loc = windows.CERT_SYSTEM_STORE_LOCAL_MACHINE
	}

	h, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM_W, 0, 0, loc, uintptr(unsafe.Pointer(storeName)))
	if err != nil {
		return nil, err
	}

	// https://github.com/golang/sys/pull/92
	if h == 0 {
		return nil, fmt.Errorf("open store failed")
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

		encoding = uintptr(windows.X509_ASN_ENCODING)
		flags    = uintptr(certChainFindByIssuerCacheOnlyFlag | certChainFindByIssuerCacheOnlyURLFlag)
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

		// rgpChain is actually an array, but we only care about the first one.
		simpleChain := *chainCtx.Chains
		if simpleChain.NumElements < 1 {
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

	if errno, ok := err.(syscall.Errno); ok && errno == syscall.Errno(windows.CRYPT_E_NOT_FOUND)  {
		goto fail
	}

	return idents, nil

fail:
	for _, ident := range idents {
		ident.Close()
	}

	return nil, err
}

type cryptDataBlob struct {
	cbData uint32
	pbData *byte
}

// Import implements the Store interface.
func (s *winStore) Import(data []byte, password string) error {
	cpw, err := windows.UTF16PtrFromString(password)
	if err != nil {
		return err
	}

	pfx := &cryptDataBlob{
		cbData: uint32(len(data)),
		pbData: &data[0],
	}

	flags := cryptUserKeyset | pkcs12AlwaysCngKsp

	store, _, err := pfxImportCertStore.Call(uintptr(unsafe.Pointer(pfx)), uintptr(unsafe.Pointer(cpw)), uintptr(flags))
	if store == 0 {
		return err
	}
	defer certCloseStore.Call(store, uintptr(certCloseStoreForceFlag))

	var (
		ctx      *windows.CertContext
		encoding = uintptr(windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING)
	)

	for {
		// iterate through certs in temporary store
		r, _, err := certFindCertificateInStore.Call(store, encoding, 0, uintptr(certFindAny), 0, uintptr(unsafe.Pointer(ctx)))

		if r == 0 {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.Errno(windows.CRYPT_E_NOT_FOUND) {
				break
			}

			return err
		}

		ctx = (*windows.CertContext)(unsafe.Pointer(r))
		r, _, err = certAddCertificateContextToStore.Call(uintptr(s.store), uintptr(unsafe.Pointer(ctx)), windows.CERT_STORE_ADD_REPLACE_EXISTING, 0)
		if r == 0 {
			return err
		}

	}

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

	if keySpec != certNcryptKeySpec {
		return nil, errors.New("cryptAcquireOnlyNcryptKeyFlag returned non cng key spec")
	}

	return &winPrivateKey{
		publicKey: publicKey,
		cngHandle: h,
	}, nil
}

// Public implements the crypto.Signer interface.
func (wpk *winPrivateKey) Public() crypto.PublicKey {
	return wpk.publicKey
}

// Sign implements the crypto.Signer interface.
func (wpk *winPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if wpk.cngHandle != 0 {
		return wpk.cngSignHash(opts, digest)
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

func (wpk *winPrivateKey) Delete() error {
	if wpk.cngHandle != 0 {
		// Delete CNG key
		r, _, err := nCryptDeleteKey.Call(wpk.cngHandle, 0)
		if r != 0 {
			return err
		}
	} else {
		return errors.New("bad private key")
	}

	return nil
}

// Close closes this winPrivateKey.
func (wpk *winPrivateKey) Close() {
	if wpk.cngHandle != 0 {
		nCryptFreeObject.Call(wpk.cngHandle)
		wpk.cngHandle = 0
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
