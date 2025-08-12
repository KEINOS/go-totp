/*
Package totp is a simple Go package to implement Timebased-One-Time-Password
authentication functionality, a.k.a. TOTP, to the Go app.

Optionally, it supports ECDH key agreement protocol to share the same secret key
between two parties.

	```shellsession
	# Install the module
	go get github.com/KEINOS/go-totp
	```

	```go
	// Use the package
	import "github.com/KEINOS/go-totp/totp"
	```
*/
package totp

import (
	"strconv"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// StrToUint converts a string to an unsigned integer. If the string is not a
// valid integer or out of range of uint32, it returns 0.
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

// Validate returns true if the given passcode is valid for the secret and
// options at the current time.
//
// The passcode should be a string of 6 or 8 digit number and the secret should
// be a base32 encoded string.
//
// Usually, Key.Validate() method is used to validate the passcode. Use this
// function if you have the values and simply want to validate the passcode.
func Validate(passcode, secret string, options Options) bool {
	validationTime := time.Now()

	return ValidateCustom(passcode, secret, validationTime, options)
}

// ValidateCustom is like Validate but allows a custom validation time.
func ValidateCustom(passcode, secret string, validationTime time.Time, options Options) bool {
	isValid, err := totp.ValidateCustom(
		passcode,
		secret,
		validationTime.UTC(),
		totp.ValidateOpts{
			Period:    options.Period,
			Skew:      options.Skew,
			Digits:    options.Digits.OTPDigits(),
			Algorithm: options.Algorithm.OTPAlgorithm(),
			Encoder:   otp.EncoderDefault,
		},
	)
	if !isValid || err != nil {
		return false
	}

	return true
}
