package totp

import (
	"strings"

	"github.com/pkg/errors"
)

// ----------------------------------------------------------------------------
//  Internal Mappings
// ----------------------------------------------------------------------------

const (
	idSHA1   = 0
	idSHA256 = 1
	idSHA512 = 2
	idMD5    = 3
	idUnknown = -1
)

// Algorithm is a string that represents the algorithm used to generate the
// passcode (for HMAC).
type Algorithm string

// Exported Constants: Use these instead of raw strings in your code.
const (
	AlgorithmMD5    Algorithm = "MD5"
	AlgorithmSHA1   Algorithm = "SHA1"
	AlgorithmSHA256 Algorithm = "SHA256"
	AlgorithmSHA512 Algorithm = "SHA512"
)

// OptionAlgorithmDefault is the default algorithm used for TOTP.
const OptionAlgorithmDefault = AlgorithmSHA1

// ----------------------------------------------------------------------------
//  Constructor
// ----------------------------------------------------------------------------

// NewAlgorithmStr creates an Algorithm value from its name.
// Available algorithms: MD5, SHA1, SHA256, SHA512.
func NewAlgorithmStr(algo string) (Algorithm, error) {
	const (
		cMD5    = "MD5"
		cSHA1   = "SHA1"
		cSHA256 = "SHA256"
		cSHA512 = "SHA512"
	)

	algo = strings.ToUpper(algo)

	switch algo {
	case cMD5, cSHA1, cSHA256, cSHA512:
		return Algorithm(algo), nil
	}

	return "", errors.New("unsupported algorithm. it should be MD5, SHA1, SHA256 or SHA512")
}

// NewAlgorithmID creates an Algorithm from its numeric ID used by the
// underlying library. This constructor is mainly for conversions and checks.
func NewAlgorithmID(algoID int) (Algorithm, error) {
	const (
		cMD5    = "MD5"
		cSHA1   = "SHA1"
		cSHA256 = "SHA256"
		cSHA512 = "SHA512"
	)

	switch algoID {
	case idSHA1:
		return cSHA1, nil
	case idSHA256:
		return cSHA256, nil
	case idSHA512:
		return cSHA512, nil
	case idMD5:
		return cMD5, nil
	}

	return "", errors.New("unsupported algorithm ID. it should be 0, 1, 2 or 3")
}

// ----------------------------------------------------------------------------
//  Methods
// ----------------------------------------------------------------------------

// ID returns the numeric ID used by the original OTP library.
// Returns -1 for undefined/unsupported algorithms.
func (algo Algorithm) ID() int {
	const (
		cMD5            = "MD5"
		cSHA1           = "SHA1"
		cSHA256         = "SHA256"
		cSHA512         = "SHA512"
	)

	switch algo {
	case cMD5:
		return idMD5 // MD5 ID in pquerna/otp
	case cSHA1:
		return idSHA1 // SHA1 ID in pquerna/otp
	case cSHA256:
		return idSHA256 // SHA256 ID in pquerna/otp
	case cSHA512:
		return idSHA512 // SHA512 ID in pquerna/otp
	default:
		return idUnknown
	}
}

// IsSupported returns true if the algorithm is supported.
func (algo Algorithm) IsSupported() bool {
	switch algo {
	case AlgorithmMD5, OptionAlgorithmDefault, AlgorithmSHA256, AlgorithmSHA512:
		return true
	}

	return false
}

// String is an implementation of the fmt.Stringer interface.
func (algo Algorithm) String() string {
	return strings.ToUpper(string(algo))
}
