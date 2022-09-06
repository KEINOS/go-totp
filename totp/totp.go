package totp

import "strconv"

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
