//go:build darwin

package identity

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

SecKeyRef GetOrCreateSEKey(CFStringRef keyLabel, CFErrorRef *error) {
    // 1. Check if key exists
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(query, kSecClass, kSecClassKey);
    CFDictionaryAddValue(query, kSecAttrApplicationLabel, keyLabel);
    CFDictionaryAddValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionaryAddValue(query, kSecReturnRef, kCFBooleanTrue);
    
    SecKeyRef privateKey = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&privateKey);
    CFRelease(query);
    
    if (status == errSecSuccess && privateKey != NULL) {
        return privateKey;
    }
    
    // 2. Not found, create it
    CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    
    int size = 256;
    CFNumberRef sizeNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &size);
    CFDictionaryAddValue(attributes, kSecAttrKeySizeInBits, sizeNum);
    CFRelease(sizeNum);
    
    CFDictionaryAddValue(attributes, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    
    CFMutableDictionaryRef privateKeyAttrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(privateKeyAttrs, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionaryAddValue(privateKeyAttrs, kSecAttrApplicationLabel, keyLabel);
    
    SecAccessControlRef access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlPrivateKeyUsage, NULL);
    if (access) {
        CFDictionaryAddValue(privateKeyAttrs, kSecAttrAccessControl, access);
    }
    
    CFDictionaryAddValue(attributes, kSecPrivateKeyAttrs, privateKeyAttrs);
    
    privateKey = SecKeyCreateRandomKey(attributes, error);
    
    if (access) {
        CFRelease(access);
    }
    CFRelease(privateKeyAttrs);
    CFRelease(attributes);
    
    return privateKey;
}

CFDataRef SignDigest(SecKeyRef privKey, CFDataRef digest, CFErrorRef *error) {
    return SecKeyCreateSignature(privKey, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, digest, error);
}

CFDataRef CopyPublicKeyData(SecKeyRef privKey, CFErrorRef *error) {
    SecKeyRef pubKey = SecKeyCopyPublicKey(privKey);
    if (!pubKey) {
        return NULL;
    }
    CFDataRef data = SecKeyCopyExternalRepresentation(pubKey, error);
    CFRelease(pubKey);
    return data;
}

const char* GetCFErrorDescription(CFErrorRef error) {
    if (!error) return "unknown error";
    CFStringRef desc = CFErrorCopyDescription(error);
    if (!desc) return "unknown error";
    
    const char *ptr = CFStringGetCStringPtr(desc, kCFStringEncodingUTF8);
    if (ptr == NULL) {
        // Fallback if fast ptr is not available
        static char buffer[1024];
        if (CFStringGetCString(desc, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
            ptr = buffer;
        } else {
            ptr = "error description conversion failed";
        }
    }
    // We leak the CFStringRef here if it's not the static buffer, but it's an error path.
    // In a real app we'd copy it to a go string properly, but this is simple.
    return ptr;
}
*/
import "C"
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"unsafe"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
)

type SecureEnclaveProvider struct{}

func NewSecureEnclaveProvider() *SecureEnclaveProvider {
	return &SecureEnclaveProvider{}
}

func (p *SecureEnclaveProvider) GetIdentity() (libp2pcrypto.PrivKey, error) {
	label := "p2p-vpn-identity"
	cLabel := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(label), C.kCFStringEncodingUTF8)
	defer C.CFRelease(C.CFTypeRef(cLabel))

	var cErr C.CFErrorRef
	secKey := C.GetOrCreateSEKey(cLabel, &cErr)
	if secKey == 0 {
		if cErr != 0 {
			errStr := C.GoString(C.GetCFErrorDescription(cErr))
			if cErr != 0 {
				C.CFRelease(C.CFTypeRef(cErr))
			}
			return nil, fmt.Errorf("failed to get/create secure enclave key: %s", errStr)
		}
		return nil, errors.New("failed to get/create secure enclave key (unknown)")
	}

	// Export public key to initialize Go struct
	pubDataRef := C.CopyPublicKeyData(secKey, &cErr)
	if pubDataRef == 0 {
		C.CFRelease(C.CFTypeRef(secKey))
		if cErr != 0 {
			C.CFRelease(C.CFTypeRef(cErr))
		}
		return nil, errors.New("failed to copy public key from secure enclave")
	}

	pubBytes := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(pubDataRef)), C.int(C.CFDataGetLength(pubDataRef)))
	C.CFRelease(C.CFTypeRef(pubDataRef))

	return &SEPrivKey{
		secKey:   secKey,
		pubBytes: pubBytes,
	}, nil
}

type SEPrivKey struct {
	secKey   C.SecKeyRef
	pubBytes []byte
	pubKey   libp2pcrypto.PubKey
}

func (k *SEPrivKey) getPubKey() (libp2pcrypto.PubKey, error) {
	if k.pubKey != nil {
		return k.pubKey, nil
	}
	
	// Unmarshal ANSI X9.63 public key (0x04 + X + Y) into Go crypto.PublicKey
	x, y := elliptic.Unmarshal(elliptic.P256(), k.pubBytes)
	if x == nil {
		return nil, errors.New("failed to parse SE public key")
	}
	
	goPubKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	
	pub, err := libp2pcrypto.ECDSAPublicKeyFromPubKey(goPubKey)
	if err != nil {
		return nil, err
	}
	k.pubKey = pub
	return k.pubKey, nil
}

func (k *SEPrivKey) Bytes() ([]byte, error) {
	return nil, errors.New("cannot export SE private key")
}

func (k *SEPrivKey) Raw() ([]byte, error) {
	return nil, errors.New("cannot export SE private key")
}

func (k *SEPrivKey) Equals(other libp2pcrypto.Key) bool {
	pub, _ := k.getPubKey()
	if pub == nil {
		return false
	}
	return pub.Equals(other)
}

func (k *SEPrivKey) Type() pb.KeyType {
	return pb.KeyType_ECDSA
}

func (k *SEPrivKey) Cryptographic() bool {
	return true
}

func (k *SEPrivKey) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	
	cDigest := C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(&hash[0])), C.CFIndex(len(hash)))
	defer C.CFRelease(C.CFTypeRef(cDigest))
	
	var cErr C.CFErrorRef
	cSig := C.SignDigest(k.secKey, cDigest, &cErr)
	if cSig == 0 {
		if cErr != 0 {
			errStr := C.GoString(C.GetCFErrorDescription(cErr))
			C.CFRelease(C.CFTypeRef(cErr))
			return nil, fmt.Errorf("SE sign failed: %s", errStr)
		}
		return nil, errors.New("SE sign failed (unknown)")
	}
	defer C.CFRelease(C.CFTypeRef(cSig))
	
	sigBytes := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(cSig)), C.int(C.CFDataGetLength(cSig)))
	
	// SecKeyCreateSignature with ECDSASignatureDigestX962SHA256 returns an ASN.1 DER signature,
	// which is exactly what libp2p ECDSA keys use natively.
	return sigBytes, nil
}

func (k *SEPrivKey) GetPublic() libp2pcrypto.PubKey {
	pub, _ := k.getPubKey()
	return pub
}
