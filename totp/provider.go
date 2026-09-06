package totp

import (
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// otpProvider defines the internal interface for OTP operations.
// This abstracts the underlying library to allow switching implementations.
type otpProvider interface {
	// generateSecret returns a base32 encoded secret. An empty secret requests a
	// randomly generated secret of options.SecretSize bytes.
	generateSecret(options Options, secret []byte) (string, error)
	// Validate checks if the passcode is valid for the given secret and options.
	validate(
		passcode, secret string,
		validationTime time.Time,
		period uint,
		skew uint,
		digits Digits,
		algorithm Algorithm,
	) (bool, error)
	// GenerateCode produces a passcode for the given secret and time.
	generateCode(secret string, genTime time.Time, period uint, digits Digits, algorithm Algorithm) (string, error)
}

// pquernaProvider is the implementation of otpProvider using github.com/pquerna/otp.
type pquernaProvider struct{}

func (pquernaProvider) generateSecret(options Options, secret []byte) (string, error) {
	// Normalize empty slices to nil to ensure the upstream library triggers random generation.
	if len(secret) == 0 {
		secret = nil
	}

	opts := totp.GenerateOpts{
		Secret:      secret,
		SecretSize:  options.SecretSize,
		Issuer:      options.Issuer,
		AccountName: options.AccountName,
		Period:      options.Period,
		Digits:      options.Digits.OTPDigits(),
		Algorithm:   options.Algorithm.OTPAlgorithm(),
		Rand:        nil,
	}

	key, err := totp.Generate(opts)
	if err != nil {
		return "", fmt.Errorf("external otp generate failed: %w", err)
	}

	return key.Secret(), nil
}

func (pquernaProvider) validate(
	passcode, secret string,
	validationTime time.Time,
	period uint,
	skew uint,
	digits Digits,
	algorithm Algorithm,
) (bool, error) {
	res, err := totp.ValidateCustom(
		passcode,
		secret,
		validationTime.UTC(),
		totp.ValidateOpts{
			Period:    period,
			Skew:      skew,
			Digits:    digits.OTPDigits(),
			Algorithm: algorithm.OTPAlgorithm(),
			Encoder:   otp.EncoderDefault,
		},
	)
	if err != nil {
		return false, fmt.Errorf("external otp validate failed: %w", err)
	}

	return res, nil
}

func (pquernaProvider) generateCode(
	secret string,
	genTime time.Time,
	period uint,
	digits Digits,
	algorithm Algorithm,
) (string, error) {
	res, err := totp.GenerateCodeCustom(
		secret,
		genTime.UTC(),
		totp.ValidateOpts{
			Period:    period,
			Digits:    digits.OTPDigits(),
			Algorithm: algorithm.OTPAlgorithm(),
			Encoder:   otp.EncoderDefault,
			Skew:      0, // Not used for generating a specific point-in-time code, but required by exhaustruct
		},
	)
	if err != nil {
		return "", fmt.Errorf("external otp generate code failed: %w", err)
	}

	return res, nil
}

func newDefaultProvider() pquernaProvider {
	return pquernaProvider{}
}
