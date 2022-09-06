package totp

import "github.com/boombuler/barcode/qr"

// FixLevel is the error correction level for QR code. Use `FixLevel*` constants
// to set the level.
type FixLevel byte

// Error correction level for QR code.
const (
	// FixLevel30 is the highest level of error correction for QR codes, capable
	// of recovering 30% of the data.
	FixLevel30 = FixLevel(qr.H)
	// FixLevel25 is a qualified error correction level for QR codes, which can
	// recover 25% of the data.
	FixLevel25 = FixLevel(qr.Q)
	// FixLevel15 is a medium error correction level for QR codes, capable of
	// recovering 15% of the data.
	FixLevel15 = FixLevel(qr.M)
	// FixLevel7 is the lowest level of error correction for QR codes and can
	// recover 7% of the data.
	FixLevel7 = FixLevel(qr.L)
	// FixLevelDefault is the default error correction level for QR codes.
	// Currently set to FixLevel15.
	FixLevelDefault = FixLevel15
)

func (f FixLevel) qrFixLevel() qr.ErrorCorrectionLevel {
	return qr.ErrorCorrectionLevel(f)
}

func (f FixLevel) isValid() bool {
	switch f {
	case FixLevel30, FixLevel25, FixLevel15, FixLevel7:
		return true
	default:
		return false
	}
}
