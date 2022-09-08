package totp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAlgorithm_golen(t *testing.T) {
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

	expect := 0
	actual := algo.ID()

	require.Equal(t, expect, actual, "unsupported algorithm should return 0 which is the default algorithm")
}

func TestAlgorithm_OTPAlgorithm(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		algo  string
		otpID int
	}{
		{"SHA1", 0}, // SHA1 is the default algorithm.
		{"SHA256", 1},
		{"SHA512", 2},
		{"MD5", 3},
		{"UNKNOWN", 0}, // Unsupported algorithm should return SHA1.
	} {
		algo := Algorithm(test.algo)

		expect := test.otpID
		actual := int(algo.OTPAlgorithm())

		require.Equal(t, expect, actual)
	}
}

func TestNewAlgorithmStr_unsupported_algo(t *testing.T) {
	t.Parallel()

	_, err := NewAlgorithmStr("BLAKE3") // BLAKE3 is not supported in the TOTP spec.

	require.Error(t, err, "unsupported algorithm should return error")
	require.Contains(t, err.Error(), "unsupported algorithm")
	require.Contains(t, err.Error(), "it should be MD5, SHA1, SHA256 or SHA512")
}

func TestNewAlgorithmID_invalid_id(t *testing.T) {
	t.Parallel()

	_, err := NewAlgorithmID(999) // 999 is not a valid ID.

	require.Error(t, err, "invalid ID should return error")
	require.Contains(t, err.Error(), "invalid algorithm ID")
	require.Contains(t, err.Error(), "it should be 0, 1, 2 or 3")
}
