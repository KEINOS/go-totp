package totp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOptions_SetDefault_adjust_len_secret_size(t *testing.T) {
	for _, test := range []struct {
		algo      string
		expectLen int
	}{
		{"MD5", 16},
		{"SHA1", 20},
		{"SHA256", 32},
		{"SHA512", 64},
	} {
		opt := Options{
			Algorithm: Algorithm(test.algo),
		}
		opt.SetDefault()

		expect := test.expectLen
		actual := int(opt.SecretSize)

		require.Equal(t, expect, actual, "SecretSize is not adjusted to the algorithm")
	}
}
