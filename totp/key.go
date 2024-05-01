package totp

import (
	"encoding/pem"
	"net/url"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/pquerna/otp/totp"
	"github.com/zeebo/blake3"
)

// BlockTypeTOTP is the type of a PEM encoded data block.
const BlockTypeTOTP = "TOTP SECRET KEY"

// ----------------------------------------------------------------------------
//  Type: Key
// ----------------------------------------------------------------------------

// Key is a struct that holds the TOTP secret and its options.
type Key struct {
	Secret  Secret  // The secret key.
	Options Options // Options to be stored.
}

// ----------------------------------------------------------------------------
//  Constructor
// ----------------------------------------------------------------------------

// GenerateKey creates a new Key object with default options. Which is:
//
//	SHA-512 hash for HMAC, 30 seconds of period, 64 byte size of secret and
//	6 digits of passcode.
//
// To customize the options, use the With* functions from the options.go file.
// For advanced customization, use GenerateKeyCustom() instead.
func GenerateKey(issuer string, accountName string, opts ...Option) (*Key, error) {
	// Create options with default values.
	optsCustom, err := NewOptions(issuer, accountName)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create options during key generation")
	}

	// Apply custom options.
	for _, fn := range opts {
		if err := fn(optsCustom); err != nil {
			return nil, errors.Wrap(err, "failed to apply custom options")
		}
	}

	return GenerateKeyCustom(*optsCustom)
}

//nolint:gochecknoglobals // allow private global variable to mock during tests
var totpGenerate = totp.Generate

// GenerateKeyCustom creates a new Key object with custom options.
//
// Usually, `GenerateKey` with options is enough for most cases. But if you need
// more control over the options, use this function.
func GenerateKeyCustom(options Options) (*Key, error) {
	internalSec := []byte{} // random by default

	if options.ecdhPrivateKey != nil && options.ecdhPublicKey != nil {
		// Generate ECDH shared secret (32 bytes)
		ecdhSecret, err := options.ecdhPrivateKey.ECDH(options.ecdhPublicKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate ECDH shared secret")
		}

		// Derivation of a secret key of length `options.SecretSize` from the
		// shared secret.
		outHash := make([]byte, options.SecretSize)

		blake3.DeriveKey(
			options.ecdhCtx, // context
			ecdhSecret,      // material
			outHash,
		)

		internalSec = outHash
	}

	tmpOpt := totp.GenerateOpts{
		Issuer:      options.Issuer,
		AccountName: options.AccountName,
		Period:      options.Period,
		SecretSize:  options.SecretSize,
		Secret:      internalSec, // random if empty
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

// GenerateKeyPEM creates a new Key object from a PEM formatted string.
//
// Deprecated: Use GenKeyFromPEM() instead. This function will be removed in
// the next major release. Currently it is an alias to GenKeyFromPEM(). For
// more information, see: https://github.com/KEINOS/go-totp/issues/14
func GenerateKeyPEM(pemKey string) (*Key, error) {
	return GenKeyFromPEM(pemKey)
}

// GenKeyFromPEM creates a new Key object from a PEM formatted string.
func GenKeyFromPEM(pemKey string) (*Key, error) {
	block, rest := pem.Decode([]byte(pemKey))

	if block != nil && block.Type == BlockTypeTOTP {
		key := &Key{
			Secret: block.Bytes,
			Options: Options{
				AccountName:    block.Headers["Account Name"],
				Algorithm:      Algorithm(block.Headers["Algorithm"]),
				Digits:         NewDigitsStr(block.Headers["Digits"]),
				ecdhCtx:        "",
				ecdhPublicKey:  nil,
				ecdhPrivateKey: nil,
				Issuer:         block.Headers["Issuer"],
				Period:         StrToUint(block.Headers["Period"]),
				SecretSize:     StrToUint(block.Headers["Secret Size"]),
				Skew:           StrToUint(block.Headers["Skew"]),
			},
		}

		return key, nil
	}

	if block != nil && len(rest) > 0 {
		return GenKeyFromPEM(string(rest))
	}

	return nil, errors.New("failed to decode PEM block containing TOTP secret key")
}

// GenerateKeyURI creates a new Key object from an TOTP uri/url.
//
// Deprecated: Use GenKeyFromURI() instead. This function will be removed in
// the next major release. Currently it is an alias to GenKeyFromURI(). For
// more information, see: https://github.com/KEINOS/go-totp/issues/14
func GenerateKeyURI(uri string) (*Key, error) {
	return GenKeyFromURI(uri)
}

// GenKeyFromURI creates a new Key object from an TOTP uri/url.
// The URL format is documented here:
//
//	https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func GenKeyFromURI(uri string) (*Key, error) {
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

//nolint:gochecknoglobals // allow private global variable to mock during tests
var pemEncodeToMemory = pem.EncodeToMemory

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

// PassCodeCustom is similar to PassCode() but allows you to specify the time
// to generate the passcode.
func (k *Key) PassCodeCustom(genTime time.Time) (string, error) {
	//nolint:wrapcheck // we won't wrap the error here
	return totp.GenerateCodeCustom(
		k.Secret.Base32(),
		genTime.UTC(),
		totp.ValidateOpts{
			Period:    k.Options.Period,
			Skew:      k.Options.Skew,
			Digits:    k.Options.Digits.OTPDigits(),
			Algorithm: k.Options.Algorithm.OTPAlgorithm(),
		},
	)
}

// PEM returns the key in PEM formatted string.
func (k *Key) PEM() (string, error) {
	out := pemEncodeToMemory(&pem.Block{
		Type: BlockTypeTOTP,
		Headers: map[string]string{
			"Account Name": k.Options.AccountName,
			"Algorithm":    k.Options.Algorithm.String(),
			"Digits":       k.Options.Digits.String(),
			"Issuer":       k.Options.Issuer,
			"Period":       strconv.FormatUint(uint64(k.Options.Period), 10),
			"Secret Size":  strconv.FormatUint(uint64(k.Options.SecretSize), 10),
			"Skew":         strconv.FormatUint(uint64(k.Options.Skew), 10),
		},
		Bytes: k.Secret.Bytes(),
	})

	if out == nil {
		return "", errors.New("failed to encode key to PEM")
	}

	return string(out), nil
}

// QRCode returns a QR code image of a specified width and height, suitable for
// registering a user's TOTP URI with many clients, such as Google-Authenticator.
func (k *Key) QRCode(fixLevel FixLevel) (*QRCode, error) {
	if !fixLevel.isValid() {
		return nil, errors.Errorf("unsupported fix level: %v", fixLevel)
	}

	qrCode := &QRCode{
		URI:   URI(k.URI()),
		Level: fixLevel,
	}

	return qrCode, nil
}

// String returns a string representation of the key in URI format.
//
// It is an implementation of the fmt.Stringer interface.
func (k *Key) String() string {
	return k.URI()
}

// URI returns the key in OTP URI format.
//
// It re-generates the URI from the values stored in the Key object and will not
// use the original URI.
func (k *Key) URI() string {
	queryVal := url.Values{}

	queryVal.Set("issuer", k.Options.Issuer)
	queryVal.Set("algorithm", k.Options.Algorithm.String())
	queryVal.Set("digits", k.Options.Digits.String())
	queryVal.Set("secret", k.Secret.Base32())
	queryVal.Set("period", strconv.FormatUint(uint64(k.Options.Period), 10))

	//nolint:exhaustruct // other fields are left blank on purpose
	urlOut := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + k.Options.Issuer + ":" + k.Options.AccountName,
		RawQuery: queryVal.Encode(),
	}

	return urlOut.String()
}

// Validate returns true if the given passcode is valid for the current time.
// For custom time, use ValidateCustom() instead.
func (k *Key) Validate(passcode string) bool {
	return Validate(
		passcode,
		k.Secret.Base32(),
		k.Options,
	)
}

// ValidateCustom returns true if the given passcode is valid for the custom time.
func (k *Key) ValidateCustom(passcode string, validationTime time.Time) bool {
	return ValidateCustom(
		passcode,
		k.Secret.Base32(),
		validationTime.UTC(),
		k.Options,
	)
}
