package pki

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/libp2p/go-libp2p/core/peer"
)

var (
	CAPubKey      *mldsa87.PublicKey
	NodeSignature []byte
)

// SelectSignatureForHandshake extracts the correct signature from dual-signature PEM.
func SelectSignatureForHandshake(pemBytes []byte, hideIP bool) string {
	targetType := "ML-DSA-87 ROUTING SIGNATURE"
	if hideIP {
		targetType = "ML-DSA-87 SIGNATURE"
	}

	var baseSig string
	rest := pemBytes
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == targetType {
			return string(pem.EncodeToMemory(block))
		}
		if block.Type == "ML-DSA-87 SIGNATURE" {
			baseSig = string(pem.EncodeToMemory(block))
		}
	}
	if baseSig != "" {
		return baseSig
	}
	return string(pemBytes)
}

// DecodeSignaturePEM extracts raw signature bytes from a PEM block.
func DecodeSignaturePEM(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || (block.Type != "ML-DSA-87 SIGNATURE" && block.Type != "ML-DSA-87 ROUTING SIGNATURE") {
		// Fallback to raw hex if not a valid PEM block
		str := strings.TrimSpace(string(pemBytes))
		if hexBytes, err := hex.DecodeString(str); err == nil {
			return hexBytes, nil
		}
		return pemBytes, nil
	}
	return block.Bytes, nil
}

// GenerateDualSignatures generates both a base signature and routing signature.
func GenerateDualSignatures(sk *mldsa87.PrivateKey, targetPeerID peer.ID, virtualIP string) ([]byte, error) {
	ctxBytes := []byte("p2p-vpn-auth")

	// 1. Generate Base Signature
	baseSigBytes := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(sk, []byte(targetPeerID.String()), ctxBytes, true, baseSigBytes); err != nil {
		return nil, fmt.Errorf("failed to sign base Peer ID: %v", err)
	}
	sigPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ML-DSA-87 SIGNATURE",
		Bytes: baseSigBytes,
	})

	// 2. Generate Routing Signature if IP provided
	if virtualIP != "" {
		routingMsg := []byte(fmt.Sprintf("%s|%s", targetPeerID.String(), virtualIP))
		routingSigBytes := make([]byte, mldsa87.SignatureSize)
		if err := mldsa87.SignTo(sk, routingMsg, ctxBytes, true, routingSigBytes); err != nil {
			return nil, fmt.Errorf("failed to sign routing info: %v", err)
		}
		routingPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "ML-DSA-87 ROUTING SIGNATURE",
			Bytes: routingSigBytes,
		})
		sigPEM = append(sigPEM, routingPEM...)
	}

	return sigPEM, nil
}

// GenerateCAKeys generates a new CA keypair.
func GenerateCAKeys() (*mldsa87.PublicKey, *mldsa87.PrivateKey, error) {
	return mldsa87.GenerateKey(rand.Reader)
}

// ReadPublicKeyBytes reads a public key from disk.
func ReadPublicKeyBytes(path string) (*mldsa87.PublicKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	// Try to decode as PEM first
	block, _ := pem.Decode(keyBytes)
	var rawKey []byte
	if block != nil {
		rawKey = block.Bytes
	} else {
		// Fallback to assuming it's raw binary
		rawKey = keyBytes
	}

	pubKey := new(mldsa87.PublicKey)
	if err := pubKey.UnmarshalBinary(rawKey); err != nil {
		return nil, err
	}
	return pubKey, nil
}
