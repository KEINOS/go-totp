package totp

import (
	"image"
	"io"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestQRCode_PNG_empty_uri(t *testing.T) {
	t.Parallel()

	qr := QRCode{
		URI:   URI(""),
		Level: FixLevelDefault,
	}

	img, err := qr.PNG(100, 100)

	require.Error(t, err, "empty URI should return error")
	require.Contains(t, err.Error(), "failed to encode URI to QR code: empty URI")
	require.Nil(t, img, "it should be nil on error")
}

//nolint:paralleltest // disable parallel test due to monkey patching during test
func TestQRCode_PNG_fail_encoding(t *testing.T) {
	origin := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=6&issuer=Example.com&period=30&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	qrCode := QRCode{
		URI:   URI(origin),
		Level: FixLevelDefault,
	}

	// Backup and defer restore
	oldPNGEncode := pngEncode
	defer func() {
		pngEncode = oldPNGEncode
	}()

	// Mock pngEncode to force return error
	pngEncode = func(w io.Writer, m image.Image) error {
		return errors.New("forced error")
	}

	img, err := qrCode.PNG(100, 100)

	require.Error(t, err, "failed to encode QR code to PNG should return error")
	require.Contains(t, err.Error(), "failed to encode QR code image to PNG")
	require.Contains(t, err.Error(), "forced error")
	require.Nil(t, img, "it should be nil on error")
}

func TestQRCode_Image_failed_to_scale(t *testing.T) {
	t.Parallel()

	origin := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=6&issuer=Example.com&period=30&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	qr := QRCode{
		URI:   URI(origin),
		Level: FixLevelDefault,
	}

	img, err := qr.Image(0, 0)

	require.Error(t, err, "failed to scale QR code should return error")
	require.Contains(t, err.Error(), "failed to scale QR code")
	require.Contains(t, err.Error(), "can not scale barcode to an image smaller than 49x49")
	require.Nil(t, img, "it should be nil on error")
}
