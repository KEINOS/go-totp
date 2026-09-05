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
	// GenerateSecret returns a base32 encoded secret.
	// If secret is empty, a random secret of secretSize is generated.
	GenerateSecret(secret []byte, secretSize uint) (string, error)
	// Validate checks if the passcode is valid for the given secret and options.
	Validate(
		passcode, secret string,
		validationTime time.Time,
		period uint,
		skew uint,
		digits Digits,
		algorithm Algorithm,
	) (bool, error)
	// GenerateCode produces a passcode for the given secret and time.
	GenerateCode(secret string, genTime time.Time, period uint, digits Digits, algorithm Algorithm) (string, error)
}

// pquernaProvider is the implementation of otpProvider using github.com/pquerna/otp.
type pquernaProvider struct{}

func (p *pquernaProvider) GenerateSecret(secret []byte, secretSize uint) (string, error) {
	const defaultPeriod = 30

	opts := totp.GenerateOpts{
		Secret:     secret,
		SecretSize: secretSize,
		Issuer:     "go-totp", // Set a default issuer to avoid "Issuer must be set" error from pquerna/otp
		AccountName: "go-totp", // Set a default account name to avoid "AccountName must be set" error from pquerna/otp
		Period:     defaultPeriod,
		Digits:     otp.DigitsSix,
		Algorithm:  otp.AlgorithmSHA1,
		Rand:       nil,
	}

	key, err := totp.Generate(opts)
	if err != nil {
		return "", fmt.Errorf("external otp generate failed: %w", err)
	}

	return key.Secret(), nil
}

func (p *pquernaProvider) Validate(
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
			Digits:    p.mapDigits(digits),
			Algorithm: p.mapAlgorithm(algorithm),
			Encoder:   otp.EncoderDefault,
		},
	)
	if err != nil {
		return false, fmt.Errorf("external otp validate failed: %w", err)
	}

	return res, nil
}

func (p *pquernaProvider) GenerateCode(
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
			Digits:    p.mapDigits(digits),
			Algorithm: p.mapAlgorithm(algorithm),
			Encoder:   otp.EncoderDefault,
			Skew:      0, // Not used for generating a specific point-in-time code, but required by exhaustruct
		},
	)
	if err != nil {
		return "", fmt.Errorf("external otp generate code failed: %w", err)
	}

	return res, nil
}

func (p *pquernaProvider) mapDigits(d Digits) otp.Digits {
	switch d {
	case DigitsSix:
		return otp.DigitsSix
	case DigitsEight:
		return otp.DigitsEight
	default:
		return otp.DigitsSix
	}
}

func (p *pquernaProvider) mapAlgorithm(a Algorithm) otp.Algorithm {
	switch a {
	case AlgorithmMD5:
		return otp.AlgorithmMD5
	case OptionAlgorithmDefault:
		return otp.AlgorithmSHA1
	case AlgorithmSHA256:
		return otp.AlgorithmSHA256
	case AlgorithmSHA512:
		return otp.AlgorithmSHA512
	default:
		// Fallback to SHA1 if it's not explicitly one of the others,
		// or return -1 as a sign of unsupported.
		// Given current go-totp logic, we return -1 for unknown.
		return otp.Algorithm(-1)
	}
}

//nolint:gochecknoglobals // allow private global variable to mock during tests
var defaultProvider otpProvider = &pquernaProvider{}
