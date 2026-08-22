package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"log"
	"os"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
)

var (
	// Handle for our persistent libp2p identity
	PersistentHandle = tpmutil.Handle(0x81000002)
)

// TPMPrivKey implements libp2p's crypto.PrivKey interface
type TPMPrivKey struct {
	tpm    *os.File
	signer crypto.Signer
	pubKey libp2pcrypto.PubKey
}

// Ensure TPMPrivKey implements crypto.PrivKey
var _ libp2pcrypto.PrivKey = (*TPMPrivKey)(nil)

func (k *TPMPrivKey) Bytes() ([]byte, error) {
	return nil, errors.New("cannot export TPM private key")
}

func (k *TPMPrivKey) Raw() ([]byte, error) {
	return nil, errors.New("cannot export TPM private key")
}

func (k *TPMPrivKey) Equals(other libp2pcrypto.Key) bool {
	return k.pubKey.Equals(other)
}

func (k *TPMPrivKey) Type() pb.KeyType {
	return pb.KeyType_ECDSA
}

func (k *TPMPrivKey) Cryptographic() bool {
	return true
}

func (k *TPMPrivKey) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return k.signer.Sign(nil, hash[:], crypto.SHA256)
}

func (k *TPMPrivKey) GetPublic() libp2pcrypto.PubKey {
	return k.pubKey
}

func (k *TPMPrivKey) Close() {
	if k.tpm != nil {
		k.tpm.Close()
	}
}

type TPMProvider struct{}

func NewTPMProvider() *TPMProvider {
	return &TPMProvider{}
}

func (p *TPMProvider) GetIdentity() (libp2pcrypto.PrivKey, error) {
	// Try standard locations
	paths := []string{"/dev/tpmrm0", "/dev/tpm0"}
	var rw *os.File
	var err error

	for _, p := range paths {
		if _, statErr := os.Stat(p); statErr == nil {
			rw, err = os.OpenFile(p, os.O_RDWR, 0600)
			if err == nil {
				break
			}
		}
	}

	if rw == nil {
		return nil, errors.New("no TPM found or accessible")
	}

	// Try to load our cached key
	key, err := client.LoadCachedKey(rw, PersistentHandle, nil)
	if err != nil {
		log.Printf("TPM: Cached identity key not found, creating a new one...")

		srk, err := client.StorageRootKeyECC(rw)
		if err != nil {
			rw.Close()
			return nil, err
		}
		defer srk.Close()

		// Template for an unrestricted signing key (ECDSA P-256)
		template := client.AKTemplateECC()
		// Modify AKTemplate to allow any signing, not just restricted attestation
		template.Attributes &^= tpm2.FlagRestricted

		key, err = client.NewCachedKey(rw, PersistentHandle, template, srk.Handle())
		if err != nil {
			rw.Close()
			return nil, err
		}
	}

	signer, err := key.GetSigner()
	if err != nil {
		rw.Close()
		return nil, err
	}

	ecdsaPub, ok := key.PublicKey().(*ecdsa.PublicKey)
	if !ok {
		rw.Close()
		return nil, errors.New("TPM key is not ECDSA")
	}

	libp2pPub, err := libp2pcrypto.ECDSAPublicKeyFromPubKey(*ecdsaPub)
	if err != nil {
		rw.Close()
		return nil, err
	}

	return &TPMPrivKey{
		tpm:    rw,
		signer: signer,
		pubKey: libp2pPub,
	}, nil
}
