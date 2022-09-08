package totp

import (
	"strconv"
	"time"

	"github.com/pquerna/otp/totp"
)

// StrToUint converts a string to an unsigned integer. If the string is not a
// valid integer or out of range of int32, it returns 0.
func StrToUint(number string) uint {
	const (
		base10  = 10
		bitSize = 32
	)

	u, err := strconv.ParseUint(number, base10, bitSize)
	if err != nil {
		return 0
	}

	return uint(u)
}

// Validate returns true if the given passcode is valid for the secret and options.
//
// The passcode should be a string of 6 or 8 digit number and the secret should
// be a base32 encoded string.
func Validate(passcode, secret string, options Options) bool {
	isValid, err := totp.ValidateCustom(
		passcode,
		secret,
		time.Now().UTC(),
		totp.ValidateOpts{
			Period:    options.Period,
			Skew:      options.Skew,
			Digits:    options.Digits.OTPDigits(),
			Algorithm: options.Algorithm.OTPAlgorithm(),
		},
	)

	if !isValid || err != nil {
		return false
	}

	return true
}
