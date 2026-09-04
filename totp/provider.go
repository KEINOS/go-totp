package totp

import (
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
	Validate(passcode, secret string, period uint, skew uint, digits Digits, algorithm Algorithm) (bool, error)
	// GenerateCode produces a passcode for the given secret and time.
	GenerateCode(secret string, genTime time.Time, period uint, digits Digits, algorithm Algorithm) (string, error)
}

// pquernaProvider is the implementation of otpProvider using github.com/pquerna/otp.
type pquernaProvider struct{}

func (p *pquernaProvider) GenerateSecret(secret []byte, secretSize uint) (string, error) {
	opts := totp.GenerateOpts{
		Secret:     secret,
		SecretSize: secretSize,
	}
	key, err := totp.Generate(opts)
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}

func (p *pquernaProvider) Validate(passcode, secret string, period uint, skew uint, digits Digits, algorithm Algorithm) (bool, error) {
	return totp.ValidateCustom(
		passcode,
		secret,
		time.Now().UTC(), // Note: The wrapper ValidateCustom in totp.go handles the time.
		totp.ValidateOpts{
			Period:    period,
			Skew:      skew,
			Digits:    p.mapDigits(digits),
			Algorithm: p.mapAlgorithm(algorithm),
			Encoder:   otp.EncoderDefault,
		},
	)
}

func (p *pquernaProvider) GenerateCode(secret string, genTime time.Time, period uint, digits Digits, algorithm Algorithm) (string, error) {
	return totp.GenerateCodeCustom(
		secret,
		genTime.UTC(),
		totp.ValidateOpts{
			Period:    period,
			Digits:    p.mapDigits(digits),
			Algorithm: p.mapAlgorithm(algorithm),
			Encoder:   otp.EncoderDefault,
		},
	)
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
	case "MD5":
		return otp.AlgorithmMD5
	case OptionAlgorithmDefault:
		return otp.AlgorithmSHA1
	case "SHA256":
		return otp.AlgorithmSHA256
	case "SHA512":
		return otp.AlgorithmSHA512
	default:
		// Fallback to SHA1 if it's not explicitly one of the others,
		// or return -1 as a sign of unsupported. 
		// Given current go-totp logic, we return -1 for unknown.
		return otp.Algorithm(-1)
	}
}

// defaultProvider is the current active OTP implementation.
var defaultProvider otpProvider = &pquernaProvider{}
