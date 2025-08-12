package totp

import (
	"bytes"
	"image"
	"image/png"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/pkg/errors"
)

// QRCode holds information to generate a QR code image.
type QRCode struct {
	URI   URI      // URI to encode.
	Level FixLevel // Error correction level.
}

// Image returns the QR code as image.Image.
// Note: The underlying library cannot scale images smaller than 49x49.
// Passing smaller sizes will return a scaling error.
func (q *QRCode) Image(width, height int) (image.Image, error) {
	uri := q.URI.String()

	// Use the configured error correction level rather than a fixed value
	qrCode, err := qr.Encode(uri, q.Level.qrFixLevel(), qr.Auto)
	if err != nil || uri == "" {
		if uri == "" {
			err = errors.New("empty URI")
		}

		return nil, errors.Wrap(err, "failed to encode URI to QR code")
	}

	qrCode, err = barcode.Scale(qrCode, width, height)
	if err != nil {
		return nil, errors.Wrap(err, "failed to scale QR code")
	}

	return qrCode, nil
}

//nolint:gochecknoglobals // allow private global variable to mock during tests
var pngEncode = png.Encode

// PNG returns a PNG image of the QR code in bytes.
// See Image() for size constraints when width/height are below 49.
func (q *QRCode) PNG(width, height int) ([]byte, error) {
	img, err := q.Image(width, height)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate QR code PNG image")
	}

	var buf bytes.Buffer

	err = pngEncode(&buf, img)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode QR code image to PNG")
	}

	return buf.Bytes(), nil
}
