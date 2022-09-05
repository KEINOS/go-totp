package totp

// Constants for the default values of the options.
const (
	OptionAlgorithmDefault  = Algorithm("SHA512") // Default algorithm
	OptionPeriodDefault     = uint(30)            // Seconds (rfc6238)
	OptionSecretSizeDefault = uint(20)            // Bytes
	OptionSkewDefault       = uint(0)             // Periods
	OptionDigitsDefault     = Digits(6)           // Six digits
)

// ----------------------------------------------------------------------------
//  Type: Options
// ----------------------------------------------------------------------------

// Options is a struct that holds the options for a TOTP key.
type Options struct {
	// Name of the secret issuer. (eg, organization, company, domain)
	Issuer string
	// Name of the User's Account. (eg, email address)
	AccountName string
	// Algorithm to use for HMAC. (Default: SHA512)
	Algorithm Algorithm
	// Number of seconds a TOTP hash is valid for. (Default: 30 seconds)
	Period uint
	// Size in size of the generated Secret. (Default: 20 bytes)
	SecretSize uint
	// Skew is the periods before or after the current time to allow.
	// Value of 1 allows up to Period of either side of the specified time.
	// Defaults to 0 allowed skews. Values greater than 1 are likely sketchy.
	Skew uint
	// Digits to request. DigitsSix or DigitsEight. (Default: DigitsSix)
	Digits Digits
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
