package totp

import "testing"

func TestOption_nil_input(t *testing.T) {
	t.Parallel()

	for index, opt := range []Option{
		WithAlgorithm(Algorithm("SHA1")),
		WithPeriod(30),
		WithSecretSize(128),
		WithSkew(0),
		WithDigits(DigitsSix),
	} {
		err := opt(nil)

		if err == nil {
			t.Errorf("Test %d: expected error, got nil", index)
		}
	}
}
