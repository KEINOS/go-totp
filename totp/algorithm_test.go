package totp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAlgorithm_golden(t *testing.T) {
	t.Parallel()

	for _, test := range []string{
		"md5", "sha1", "sha256", "sha512",
		"MD5", "SHA1", "SHA256", "SHA512",
	} {
		// NewAlgorithm()
		algo1, err := NewAlgorithmStr(test)
		require.NoError(t, err)

		expect := strings.ToUpper(test)
		actual := algo1.String()

		require.Equal(t, expect, actual, "output string should be upper case")

		// Use the previous object's ID output to create a new Algorithm object.
		algo2, err := NewAlgorithmID(algo1.ID())
		require.NoError(t, err)

		require.Equal(t, algo1.String(), algo2.String())
	}
}

func TestAlgorithm_IsSupported_golden(t *testing.T) {
	t.Parallel()

	for _, tt := range []string{
		"md5", "sha1", "sha256", "sha512",
		"MD5", "SHA1", "SHA256", "SHA512",
	} {
		// NewAlgorithm()
		algo, err := NewAlgorithmStr(tt)

		require.NoError(t, err)
		require.True(t, algo.IsSupported(), "supported algorithm should return true")
	}
}

func TestAlgorithm_ID_unsupported(t *testing.T) {
	t.Parallel()

	algo := Algorithm("BLAKE3")

	expect := -1
	actual := algo.ID()

	require.Equal(t, expect, actual, "unsupported algorithm should return -1 which is the unknown algorithm")
}

// TestAlgorithm_OTPAlgorithm is deprecated as OTPAlgorithm() is now internal to the provider.
func TestAlgorithm_OTPAlgorithm(t *testing.T) {
	t.Parallel()
	_ = t
	// This test is now effectively a no-op or should be removed.
	// For now, we'll just skip its logic.
}

func TestNewAlgorithmStr_unsupported_algo(t *testing.T) {
	t.Parallel()

	_, err := NewAlgorithmStr("BLAKE3") // BLAKE3 is not supported in the TOTP spec.

	require.Error(t, err, "unsupported algorithm should return error")
	require.Contains(t, err.Error(), "unsupported algorithm")
	require.Contains(t, err.Error(), "it should be")
}

func TestNewAlgorithmID_invalid_id(t *testing.T) {
	t.Parallel()

	_, err := NewAlgorithmID(999) // 999 is not a valid ID.

	require.Error(t, err, "unsupported ID should return error")
	require.Contains(t, err.Error(), "unsupported algorithm ID")
	require.Contains(t, err.Error(), "it should be")
}
