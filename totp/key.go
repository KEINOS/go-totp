package totp

import (
	"time"

	"github.com/pkg/errors"
	"github.com/pquerna/otp/totp"
)

// ----------------------------------------------------------------------------
//  Type: Key
// ----------------------------------------------------------------------------

// Key is a struct that holds the TOTP secret and its options.
type Key struct {
	Options Options // Options to be stored.
	Secret  Secret  // The secret key.
}

// ----------------------------------------------------------------------------
//  Constructor
// ----------------------------------------------------------------------------

// GenerateKey creates a new Key object with default options. Which is:
//
//	SHA-512 hash for HMAC, 30 seconds of period, 64 byte size of secret and
//	6 digits of passcode.
//
// To specify custom options, use GenerateKeyCustom().
func GenerateKey(issuer string, accountName string) (*Key, error) {
	//nolint:exhaustruct // allow fields to be missing  so to set defaults later
	opt := Options{
		Issuer:      issuer,
		AccountName: accountName,
	}

	opt.SetDefault()

	return GenerateKeyCustom(opt)
}

//nolint:gochecknoglobals // allow private global variable to mock during tests
var totpGenerate = totp.Generate

// GenerateKeyCustom creates a new Key object with custom options. With this
// function you can specify the algorithm, period, secret size and digits.
func GenerateKeyCustom(options Options) (*Key, error) {
	tmpOpt := totp.GenerateOpts{
		Issuer:      options.Issuer,
		AccountName: options.AccountName,
		Period:      options.Period,
		SecretSize:  options.SecretSize,
		Secret:      []byte{},
		Digits:      options.Digits.OTPDigits(),
		Algorithm:   options.Algorithm.OTPAlgorithm(),
		Rand:        nil,
	}

	keyOrig, err := totpGenerate(tmpOpt)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate key")
	}

	secret, err := NewSecretBase32(keyOrig.Secret())
	if err != nil {
		return nil, errors.Wrap(err, "failed to create secret")
	}

	key := &Key{
		Secret:  secret,
		Options: options,
	}

	return key, nil
}

// GenerateKeyURI creates a new Key object from an TOTP uri/url.
//
// The URL format is documented here:
//
//	https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func GenerateKeyURI(uri string) (*Key, error) {
	objURI := URI(uri)

	if err := objURI.Check(); err != nil {
		return nil, errors.Wrap(err, "failed to create URI object from the given URI")
	}

	// Create KEY object with default options.
	key, err := GenerateKey(objURI.Issuer(), objURI.AccountName())
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate key")
	}

	// Update options
	secret := objURI.Secret()
	lenSecret := len(secret.Bytes())

	key.Secret = secret
	key.Options.SecretSize = uint(lenSecret)

	key.Options.Period = objURI.Period()
	key.Options.Algorithm = Algorithm(objURI.Algorithm())
	key.Options.Digits = Digits(objURI.Digits())

	return key, nil
}

// ----------------------------------------------------------------------------
//  Methods
// ----------------------------------------------------------------------------

// PassCode generates a 6 or 8 digits passcode for the current time.
// The output string will be eg. "123456" or "12345678".
func (k *Key) PassCode() (string, error) {
	//nolint:wrapcheck // we won't wrap the error here
	return totp.GenerateCodeCustom(
		k.Secret.Base32(),
		time.Now().UTC(),
		totp.ValidateOpts{
			Period:    k.Options.Period,
			Skew:      k.Options.Skew,
			Digits:    k.Options.Digits.OTPDigits(),
			Algorithm: k.Options.Algorithm.OTPAlgorithm(),
		},
	)
}

// Validate returns true if the given passcode is valid for the current time.
func (k *Key) Validate(passcode string) (bool, error) {
	//nolint:wrapcheck // we won't wrap the error here
	return totp.ValidateCustom(
		passcode,
		k.Secret.Base32(),
		time.Now().UTC(),
		totp.ValidateOpts{
			Period:    k.Options.Period,
			Skew:      k.Options.Skew,
			Digits:    k.Options.Digits.OTPDigits(),
			Algorithm: k.Options.Algorithm.OTPAlgorithm(),
		},
	)
}
