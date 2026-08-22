package identity

import (
	"os"

	"github.com/libp2p/go-libp2p/core/crypto"
)

// FileProvider implements the Provider interface for file-backed identities.
type FileProvider struct {
	Path string
}

func NewFileProvider(path string) *FileProvider {
	return &FileProvider{
		Path: path,
	}
}

func (p *FileProvider) GetIdentity() (crypto.PrivKey, error) {
	if _, err := os.Stat(p.Path); err == nil {
		data, err := os.ReadFile(p.Path)
		if err == nil {
			return crypto.UnmarshalPrivateKey(data)
		}
	}
	priv, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		return nil, err
	}
	data, _ := crypto.MarshalPrivateKey(priv)
	os.WriteFile(p.Path, data, 0600)
	return priv, nil
}
