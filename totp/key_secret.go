package totp

import (
	"encoding/base32"
	"math/big"

	"github.com/pkg/errors"
)

// ----------------------------------------------------------------------------
//  Type: Secret
// ----------------------------------------------------------------------------

// Secret is a byte slice that represents a secret key.
type Secret []byte

// ----------------------------------------------------------------------------
//  Constructiors
// ----------------------------------------------------------------------------

// NewSecretBytes creates a new Secret object from a byte slice.
func NewSecretBytes(input []byte) Secret {
	return Secret(input)
}

// NewSecretBase32 creates a new Secret object from a base32 encoded string.
func NewSecretBase32(base32string string) (Secret, error) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(base32string)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode base32 string")
	}

	return Secret(decoded), nil
}

// NewSecretBase62 creates a new Secret object from a base62 encoded string.
func NewSecretBase62(base62string string) (Secret, error) {
	var i big.Int

	encBase62 := 62

	decoded, ok := i.SetString(base62string, encBase62)
	if !ok {
		return nil, errors.New("failed to decode base62 string")
	}

	return Secret(decoded.Bytes()), nil
}

// ----------------------------------------------------------------------------
//  Methods
// ----------------------------------------------------------------------------

// Base32 returns the secret as a base32 encoded string.
// Which is the standard format used by TOTP URIs.
func (s Secret) Base32() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(s)
}

// Base62 returns the secret as a base62 encoded string.
func (s Secret) Base62() string {
	var i big.Int

	encBase62 := 62

	return i.SetBytes(s[:]).Text(encBase62)
}

// Bytes returns the secret as a byte slice.
func (s Secret) Bytes() []byte {
	return s
}

// String is an implementation of the Stringer interface. It is an alias for
// Base32().
func (s Secret) String() string {
	return s.Base32()
}
