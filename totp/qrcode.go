package totp

import (
	"bytes"
	"image"
	"image/png"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/pkg/errors"
)

// QRCode is a struct that holds the information to create QR code image.
type QRCode struct {
	URI   URI      // URI object to be encoded to QR code image.
	Level FixLevel // Level is the error correction level for the QR code.
}

// Image returns an image.Image object of the QR code. Minimum width and height
// is 49x49.
func (q *QRCode) Image(width, height int) (image.Image, error) {
	uri := q.URI.String()

	qrCode, err := qr.Encode(uri, qr.M, qr.Auto)
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

// PNG returns a PNG image of the QR code in bytes. Minimum width and height
// is 49x49.
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
