package totp

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
//  NewSecretBase32()
// ----------------------------------------------------------------------------

func TestNewSecretBase32_invalid_string(t *testing.T) {
	t.Parallel()

	_, err := NewSecretBase32("invalid string")

	require.Error(t, err, "invalid string should return error")
	require.Contains(t, err.Error(), "failed to decode base32 string")
}

// ----------------------------------------------------------------------------
//  NewSecretBase62()
// ----------------------------------------------------------------------------

func TestNewSecretBase62_invalid_string(t *testing.T) {
	t.Parallel()

	_, err := NewSecretBase62("invalid string")

	require.Error(t, err, "invalid string should return error")
	require.Contains(t, err.Error(), "failed to decode base62 string")
}

// ----------------------------------------------------------------------------
//  Secret.Base32()
// ----------------------------------------------------------------------------

func TestSecret_Base32_golden(t *testing.T) {
	t.Parallel()

	input := []byte("foo bar buzz")
	secret := Secret(input)

	expect := "MZXW6IDCMFZCAYTVPJ5A" // Base32
	actual := secret.Base32()

	require.Equal(t, expect, actual)
	require.Equal(t, secret.Base32(), secret.String(),
		"method String() should be an alias for Base32()")
}

// ----------------------------------------------------------------------------
//  Secret.Base62()
// ----------------------------------------------------------------------------

func TestSecret_Base62_golden(t *testing.T) {
	t.Parallel()

	input := "foo bar buzz"

	// Ceate secret object
	secret := Secret([]byte(input))

	// Encoding test
	expect1 := "FegjEGvm7g03GQye" // Base62
	actual1 := secret.Base62()

	require.Equal(t, expect1, actual1, "the Base62 encoding failed")

	// Decoding test
	i := new(big.Int)

	i.SetString(actual1, 62)

	expect2 := []byte(input)
	actual2 := i.Bytes()

	require.Equal(t, expect2, actual2, "decoded bytes should match the original input")
}

// ----------------------------------------------------------------------------
//  Secret.Bytes()
// ----------------------------------------------------------------------------

func TestSecret_Bytes_golden(t *testing.T) {
	t.Parallel()

	input := []byte("foo bar buzz")
	secret := Secret(input)

	expect := input
	actual := secret.Bytes()

	require.Equal(t, expect, actual)
}
