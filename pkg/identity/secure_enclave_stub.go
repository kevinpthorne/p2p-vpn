//go:build !darwin

package identity

import (
	"errors"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
)

type SecureEnclaveProvider struct{}

func NewSecureEnclaveProvider() *SecureEnclaveProvider {
	return &SecureEnclaveProvider{}
}

func (p *SecureEnclaveProvider) GetIdentity() (libp2pcrypto.PrivKey, error) {
	return nil, errors.New("Secure Enclave is not supported on this operating system")
}
