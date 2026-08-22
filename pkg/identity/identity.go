package identity

import (
	"github.com/libp2p/go-libp2p/core/crypto"
)

// Provider defines the interface for loading and managing a libp2p identity.
type Provider interface {
	// GetIdentity returns the libp2p private key identity.
	GetIdentity() (crypto.PrivKey, error)
}
