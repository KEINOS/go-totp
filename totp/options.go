package totp

import "github.com/pkg/errors"

// Constants for the default values of the options.
const (
	OptionAlgorithmDefault  = Algorithm("SHA1") // Google Authenticator does not work other than SHA1.
	OptionPeriodDefault     = uint(30)          // 30 seconds is recommended in RFC-6238.
	OptionSecretSizeDefault = uint(128)         // 128 Bytes.
	OptionSkewDefault       = uint(0)           // ± Periods. No tolerance.
	OptionDigitsDefault     = Digits(6)         // Google Authenticator does not work other than 6 digits.
)

// ----------------------------------------------------------------------------
//  Type: Options
// ----------------------------------------------------------------------------

// Options is a struct that holds the options for a TOTP key.
type Options struct {
	// Issuer is the name of the issuer of the secret key. (eg, organization, company, domain)
	Issuer string
	// AccountName is the name of the secret key owner. (eg, email address)
	AccountName string
	// Algorithm to use for HMAC. (Default: Algorithm("SHA512"))
	Algorithm Algorithm
	// Period is the number of seconds a TOTP hash is valid for. (Default: 30 seconds)
	Period uint
	// SecretSize is the size of the generated Secret. (Default: 128 bytes)
	SecretSize uint
	// Skew is the periods before or after the current time to allow.
	// Value of 1 allows up to Period of either side of the specified time.
	// Defaults to 0 allowed skews. Values greater than 1 are likely sketchy.
	Skew uint
	// Digits to request TOTP code. DigitsSix or DigitsEight. (Default: DigitsSix)
	Digits Digits
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

	// This is redundant, but it's here to make sure that the default value is
	// always set.
	if opts.Skew == 0 {
		opts.Skew = OptionSkewDefault
	}
}
