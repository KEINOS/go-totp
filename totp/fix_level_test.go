package totp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFixLevel_golden(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		fixLevel FixLevel
		expected byte
	}{
		{FixLevel30, 3},
		{FixLevel25, 2},
		{FixLevel15, 1},
		{FixLevel7, 0},
		{FixLevelDefault, 1},
	} {
		expect := test.expected
		actual := test.fixLevel.qrFixLevel()

		require.Equal(t, uint(expect), uint(actual))
	}
}
