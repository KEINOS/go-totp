package totp

import "github.com/pquerna/otp"

// ----------------------------------------------------------------------------
//  Type: Digits
// ----------------------------------------------------------------------------

// Digits represents the number of digits present in the user's OTP passcode.
// Six and Eight are the most common values.
type Digits uint

const (
	// DigitsSix is the default number of digits in a TOTP passcode.
	DigitsSix Digits = 6
	// DigitsEight is an alternative number of digits in a TOTP passcode.
	DigitsEight Digits = 8
)

// ----------------------------------------------------------------------------
//  Constructor
// ----------------------------------------------------------------------------

// NewDigits returns a new Digits object from the given value.
func NewDigits(digits int) Digits {
	return Digits(uint(digits))
}

// ----------------------------------------------------------------------------
//  Methods
// ----------------------------------------------------------------------------

// OTPDigits returns the value in otp.Digits type. Undefined Digits will always
// return otp.DigitsSix.
func (d Digits) OTPDigits() otp.Digits {
	switch d {
	case DigitsSix:
		return otp.DigitsSix
	case DigitsEight:
		return otp.DigitsEight
	}

	return otp.DigitsSix
}
