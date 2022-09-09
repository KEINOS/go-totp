package totp

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/pquerna/otp"
)

// ----------------------------------------------------------------------------
//  Type: Algorithm
// ----------------------------------------------------------------------------

// Algorithm is a string that represents the algorithm used for HMAC.
type Algorithm string

// ----------------------------------------------------------------------------
//  Constructor
// ----------------------------------------------------------------------------

// NewAlgorithmStr creates a new Algorithm object from a string.
// Choices are: MD5, SHA1, SHA256 and SHA512.
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

// NewAlgorithmID creates a new Algorithm object from an int.
func NewAlgorithmID(algoID int) (Algorithm, error) {
	const (
		cMD5    = "MD5"
		cSHA1   = "SHA1"
		cSHA256 = "SHA256"
		cSHA512 = "SHA512"
	)

	switch algoID {
	case int(otp.AlgorithmSHA1):
		return cSHA1, nil
	case int(otp.AlgorithmSHA256):
		return cSHA256, nil
	case int(otp.AlgorithmSHA512):
		return cSHA512, nil
	case int(otp.AlgorithmMD5):
		return cMD5, nil
	}

	return "", errors.New("invalid algorithm ID. it should be 0, 1, 2 or 3")
}

// ----------------------------------------------------------------------------
//  Methods
// ----------------------------------------------------------------------------

// ID returns the ID of the algorithm which is the same int value as the
// original OTP library.
//
// Undefined ID will always return 2 (SHA512).
func (algo Algorithm) ID() int {
	const (
		cMD5            = "MD5"
		cSHA1           = "SHA1"
		cSHA256         = "SHA256"
		cSHA512         = "SHA512"
		UnsupportedAlgo = -1 // see issue #6
	)

	switch algo {
	case cMD5:
		return int(otp.AlgorithmMD5)
	case cSHA1:
		return int(otp.AlgorithmSHA1)
	case cSHA256:
		return int(otp.AlgorithmSHA256)
	case cSHA512:
		return int(otp.AlgorithmSHA512)
	default:
		return UnsupportedAlgo
	}
}

// IsSupported returns true if the algorithm is supported.
func (algo Algorithm) IsSupported() bool {
	switch algo {
	case "MD5", OptionAlgorithmDefault, "SHA256", "SHA512":
		return true
	}

	return false
}

// OTPAlgorithm is similar to ID() but returns in the original type of the OTP
// library.
//
// Undefined Algorithm type will always return `otp.AlgorithmSHA512`.
func (algo Algorithm) OTPAlgorithm() otp.Algorithm {
	switch algo {
	case "MD5":
		return otp.AlgorithmMD5
	case OptionAlgorithmDefault: // SHA1
		return otp.AlgorithmSHA1
	case "SHA256":
		return otp.AlgorithmSHA256
	case "SHA512":
		return otp.AlgorithmSHA512
	default:
		return otp.Algorithm(-1) // fix: issue #6
	}
}

// String is an implementation of the Stringer interface.
func (algo Algorithm) String() string {
	return strings.ToUpper(string(algo))
}
