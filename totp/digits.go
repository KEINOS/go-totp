package totp

import (
	"fmt"

	"github.com/pquerna/otp"
)

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

// NewDigitsInt returns a new Digits object from the given value. If the value
// is less than zero, it will return DigitsSix.
func NewDigitsInt(digits int) Digits {
	if digits < 0 {
		return DigitsSix
	}

	return Digits(uint(digits))
}

// NewDigitsStr returns a new Digits object from the given string in decimal
// format.
func NewDigitsStr(digits string) Digits {
	return Digits(StrToUint(digits))
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

// String returns the string representation of the Digits.
func (d Digits) String() string {
	return fmt.Sprintf("%d", d)
}
