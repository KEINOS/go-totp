package totp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOptionKDFDefault_golden(t *testing.T) {
	t.Parallel()

	wantLen := 32
	origSecret := []byte("secret")
	ctx := []byte("context")
	outLen := uint(wantLen)

	newSecret, err := OptionKDFDefault(origSecret, ctx, outLen)

	require.NoError(t, err,
		"failed to derive key during test")
	require.Len(t, newSecret, wantLen,
		"unexpected length of derived key during test")
	require.NotEqual(t, origSecret, newSecret,
		"derived key must not be the same as the original secret")
}

func TestOptionKDFDefault_invalid_length(t *testing.T) {
	t.Parallel()

	origSecret := []byte("secret")
	ctx := []byte("context")

	t.Run("length_zero", func(t *testing.T) {
		t.Parallel()

		outLen := uint(0)
		newSecret, err := OptionKDFDefault(origSecret, ctx, outLen)

		require.Error(t, err,
			"requesting key with length 0 should return an error")
		require.Nil(t, newSecret,
			"returned key must be nil on error")
		require.Contains(t, err.Error(), "invalid output length",
			"error message must contain the error reason")
	})

	t.Run("length_negative", func(t *testing.T) {
		t.Parallel()

		negativeLen := (int)(-8)
		outLen := uint(negativeLen)
		newSecret, err := OptionKDFDefault(origSecret, ctx, outLen)

		require.Error(t, err,
			"requesting key with length 0 should return an error")
		require.Contains(t, err.Error(), "output length too large",
			"error message must contain the error reason")
		require.Nil(t, newSecret,
			"returned key must be nil on error")
	})
}
