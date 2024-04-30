package totp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
//  Type: Option
// ----------------------------------------------------------------------------

func TestOption_nil_input(t *testing.T) {
	t.Parallel()

	for index, fnOpt := range []Option{
		WithAlgorithm(Algorithm("SHA1")),
		WithECDH(nil, nil, ""),
		WithPeriod(30),
		WithSecretSize(128),
		WithSkew(0),
		WithDigits(DigitsSix),
	} {
		// functions shuold return error when nil input is given.
		err := fnOpt(nil)

		require.Error(t, err, "Test %d: expected error, got nil", index)
	}
}
