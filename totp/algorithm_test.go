package totp

import (
	"strings"
	"testing"

	"github.com/pquerna/otp"
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

func TestNewAlgorithmStr_unsupported_algo(t *testing.T) {
	t.Parallel()

	_, err := NewAlgorithmStr("BLAKE3") // BLAKE3 is not supported in the TOTP spec.

	require.Error(t, err, "unsupported algorithm should return error")
	require.Contains(t, err.Error(), "unsupported algorithm")
}

func TestNewAlgorithmID_invalid_id(t *testing.T) {
	t.Parallel()

	_, err := NewAlgorithmID(999) // 999 is not a valid ID.

	require.Error(t, err, "unsupported ID should return error")
	require.Contains(t, err.Error(), "unsupported algorithm ID")
}

func TestAlgorithm_OTPAlgorithm(t *testing.T) {
	t.Parallel()

	tests := map[Algorithm]otp.Algorithm{
		AlgorithmMD5:    otp.AlgorithmMD5,
		AlgorithmSHA1:   otp.AlgorithmSHA1,
		AlgorithmSHA256: otp.AlgorithmSHA256,
		AlgorithmSHA512: otp.AlgorithmSHA512,
		"UNKNOWN":       otp.Algorithm(-1),
	}

	for algorithm, want := range tests {
		require.Equal(t, want, algorithm.OTPAlgorithm())
	}
}
