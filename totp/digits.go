package totp

import (
	"fmt"
)

// ----------------------------------------------------------------------------
//  Type: Digits
// ----------------------------------------------------------------------------

// Digits represents the number of digits in the OTP code.
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

// String is an implementation of the fmt.Stringer interface.
func (d Digits) String() string {
	return fmt.Sprintf("%d", d)
}
