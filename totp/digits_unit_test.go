package totp

import (
	"testing"

	"github.com/pquerna/otp"
	"github.com/stretchr/testify/require"
)

func TestDigits_OTPDigits(t *testing.T) {
	t.Parallel()

	tests := map[Digits]otp.Digits{
		DigitsSix:   otp.DigitsSix,
		DigitsEight: otp.DigitsEight,
		Digits(7):   otp.DigitsSix,
	}

	for digits, want := range tests {
		require.Equal(t, want, digits.OTPDigits())
	}
}
