package totp

import (
	"crypto/ecdh"

	"github.com/pkg/errors"
)

// Constants for the default values of the options.
const (
	OptionAlgorithmDefault  = Algorithm("SHA1") // Google Authenticator does not work other than SHA1.
	OptionDigitsDefault     = Digits(6)         // Google Authenticator does not work other than 6 digits.
	OptionPeriodDefault     = uint(30)          // 30 seconds is recommended in RFC-6238.
	OptionSecretSizeDefault = uint(128)         // 128 Bytes.
	OptionSkewDefault       = uint(1)           // ± 1 period of tolerance.
)

// ============================================================================
//  Type: Options
// ============================================================================

// Options is a struct that holds the options for a TOTP key. Use SetDefault()
// to set the default values.
type Options struct {
	// AccountName is the name of the secret key owner. (eg, email address)
	AccountName string
	// Algorithm to use for HMAC to generate the TOTP passcode.
	// (Default: Algorithm("SHA1"))
	//
	// Note that this is not the same hash algorithm used for the secret key
	// generated via ECDH.
	Algorithm Algorithm
	// Digits to request TOTP code. DigitsSix or DigitsEight. (Default: DigitsSix)
	Digits Digits
	// Context used for generating TOTP secret from ECDH shared secret. If both
	// ecdhPrivateKey and ecdhPublicKey are set, this context will be used.
	ecdhCtx string
	// ECDH private key. If both ecdhPrivateKey and ecdhPublicKey are set, the
	// secret will be generated from them.
	ecdhPrivateKey *ecdh.PrivateKey
	// ECDH public key of the correspondent. If both ecdhPrivateKey and ecdhPublicKey
	// are set, the secret will be generated from them.
	ecdhPublicKey *ecdh.PublicKey
	// Issuer is the name of the issuer of the secret key.
	// (eg, organization, company, domain)
	Issuer string
	// Period is the number of seconds a TOTP hash is valid for.
	// (Default: 30 seconds)
	Period uint
	// SecretSize is the size of the generated Secret. (Default: 128 bytes)
	SecretSize uint
	// Skew is the periods before or after the current time to allow. (Default: 1)
	//
	// Value of 1 allows up to Period of either side of the specified time.
	// Values greater than 1 are likely sketchy.
	Skew uint
}

// ----------------------------------------------------------------------------
//  Constructor
// ----------------------------------------------------------------------------

// NewOptions returns a new Options struct with the default values.
// Issuer and AccountName are required.
func NewOptions(issuer, accountName string) (*Options, error) {
	if issuer == "" || accountName == "" {
		return nil, errors.New("issuer and accountName are required")
	}

	opt := new(Options)
	opt.SetDefault()

	opt.Issuer = issuer
	opt.AccountName = accountName

	return opt, nil
}

// ----------------------------------------------------------------------------
//  Methods
// ----------------------------------------------------------------------------

// SetDefault sets the undefined options to its default value.
func (opts *Options) SetDefault() {
	if opts.Algorithm == "" {
		opts.Algorithm = OptionAlgorithmDefault
	}

	if opts.Period == 0 {
		opts.Period = OptionPeriodDefault
	}

	if opts.SecretSize == 0 {
		opts.SecretSize = OptionSecretSizeDefault
	}

	if opts.Digits == 0 {
		opts.Digits = OptionDigitsDefault
	}

	// Fix #42
	if opts.Skew == 0 {
		opts.Skew = OptionSkewDefault
	}
}
