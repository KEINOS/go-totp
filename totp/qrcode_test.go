package totp

import (
	"bytes"
	"image"
	"image/png"
	"io"
	"testing"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestQRCode_PNG_golden(t *testing.T) {
	t.Parallel()

	testURI := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=6&issuer=Example.com&period=2&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	key, err := GenerateKeyURI(testURI)
	require.NoError(t, err, "the test URI is invalid")

	uri := key.URI()
	require.Equal(t, testURI, uri)

	qrCode, err := key.QRCode(FixLevelDefault)
	require.NoError(t, err, "failed to generate QR code during test setup")

	// Generate PNG image via method
	pngImg1, err := qrCode.PNG(100, 100)
	require.NoError(t, err, "failed to generate PNG image from method during test setup")

	// Generate PNG image via test function
	pngImg2 := genPNG(t, uri, 100, 100)

	// Compare images
	require.Equal(t, pngImg1, pngImg2, "the generated PNG images should be the same")

	// Validate passcode in-time
	passcode, err := key.PassCode()
	require.NoError(t, err, "failed to generate passcode during test")

	ok := key.Validate(passcode)
	require.True(t, ok, "the passcode should be valid")
}

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
	pngEncode = func(_ io.Writer, _ image.Image) error {
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

// ----------------------------------------------------------------------------
//  Helper functions
// ----------------------------------------------------------------------------

// genPNG generates a PNG image from the given URI. It is a naive implementation
// of QRCode.PNG() for testing purpose.
func genPNG(t *testing.T, uri string, width, height int) []byte {
	t.Helper()

	qrCode, err := qr.Encode(uri, FixLevel15.qrFixLevel(), qr.Auto)
	if err != nil {
		t.Fatal(err)
	}

	qrCode, err = barcode.Scale(qrCode, width, height)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer

	err = png.Encode(&buf, qrCode)
	if err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}
