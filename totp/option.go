package totp

import (
	"crypto/ecdh"

	"github.com/pkg/errors"
)

// ============================================================================
//  Type: Option
// ============================================================================

// Option is a function that applies an option to the given Options.
// It should return an error if the option is nil or invalid.
type Option func(*Options) error

const errNilOptions = "options is nil"

// ----------------------------------------------------------------------------
//  Option Patterns
// ----------------------------------------------------------------------------

// WithAlgorithm sets the Algorithm to use for HMAC (Default: Algorithm("SHA512")).
func WithAlgorithm(algo Algorithm) Option {
	return func(opts *Options) error {
		if opts == nil {
			return errors.New(errNilOptions)
		}

		if !algo.IsSupported() {
			return errors.New("unsupported algorithm: " + algo.String())
		}

		opts.Algorithm = algo

		return nil
	}
}

// WithDigits sets the Digits to request TOTP code. Choices are DigitsSix or
// DigitsEight (Default: DigitsSix).
func WithDigits(digits Digits) Option {
	return func(opts *Options) error {
		if opts == nil {
			return errors.New(errNilOptions)
		}

		opts.Digits = digits

		return nil
	}
}

// WithECDH sets a hashed ECDH shared secret as the TOTP secret from the given
// ECDH private key and the correspondent's ECDH public key.
//
// Important:
//
//   - Both ECDH keys must be generated from the same curve type.
//
//   - context is required as a consistent string between the two parties.
//
//     Both parties must use the same context to generate the same shared secret.
//     The context string can be anything, but it must be consistent between the
//     two parties. The recommended format is:
//
//     "[issuer] [sorted account names] [purpose] [version]"
//
//     e.g.) "example.com alice@example.com bob@example.com TOTP secret v1"
func WithECDH(localKey *ecdh.PrivateKey, remoteKey *ecdh.PublicKey, context string) Option {
	return func(opts *Options) error {
		if opts == nil {
			return errors.New(errNilOptions)
		}

		// Set ECDH keys as option info. The actual secret generation is done
		// when the Key is created. See GenerateKeyCustom().
		opts.ecdhPrivateKey = localKey
		opts.ecdhPublicKey = remoteKey
		opts.ecdhCtx = context

		return nil
	}
}

// WithECDHKDF sets the userKDF, user definded key derivation function, to derive
// a TOTP secret key from a ECDH shared secret.
//
// The function must implement the totp.KDF interface.
func WithECDHKDF(userKDF func(secret, ctx []byte, outLen uint) ([]byte, error)) Option {
	return func(opts *Options) error {
		if opts == nil {
			return errors.New(errNilOptions)
		}

		opts.kdf = userKDF

		return nil
	}
}

// WithPeriod sets the number of seconds a TOTP hash is valid for (Default: 30 seconds).
func WithPeriod(period uint) Option {
	return func(opts *Options) error {
		if opts == nil {
			return errors.New(errNilOptions)
		}

		opts.Period = period

		return nil
	}
}

// WithSecretSize sets the size of the generated Secret (Default: 128 bytes).
func WithSecretSize(size uint) Option {
	return func(opts *Options) error {
		if opts == nil {
			return errors.New(errNilOptions)
		}

		opts.SecretSize = size

		return nil
	}
}

// WithSecretQueryFirst sets whether the secret should be the first query parameter in the URI.
// When true (default), secret appears first: "?secret=...&algorithm=...".
// When false, parameters are sorted alphabetically: "?algorithm=...&secret=...".
func WithSecretQueryFirst(choice bool) Option {
	return func(opts *Options) error {
		opts.prependSecretInURI = choice

		return nil
	}
}

// WithSkew sets the periods before or after the current time to allow.
//
// Value of 1 allows up to Period of either side of the specified time.
// Defaults to 1 allowed skews. Values greater than 1 are likely sketchy.
func WithSkew(skew uint) Option {
	return func(opts *Options) error {
		if opts == nil {
			return errors.New(errNilOptions)
		}

		opts.Skew = skew

		return nil
	}
}
