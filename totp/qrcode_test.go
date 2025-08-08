package totp

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"io"
	"testing"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
//  Basic Tests
// ----------------------------------------------------------------------------

func TestQRCode_PNG_golden(t *testing.T) {
	t.Parallel()

	// Note that the "secret" query parameter is at the end of the URI.
	inputURI := "otpauth://totp/Example.com:alice@example.com?" +
		"algorithm=SHA1&digits=6&issuer=Example.com&period=2&" +
		"secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	key, err := GenerateKeyURI(inputURI)
	require.NoError(t, err,
		"the test URI is invalid")

	uri := key.URI()

	// As of 0.3.0, the secret is the first query parameter in the URI by default.
	// To change this behavior (be all the query parameters sorted alphabetically),
	// use the WithSecretQueryFirst(false) option when generating the key.
	expectURI := "otpauth://totp/Example.com:alice@example.com?" +
		"secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3&" +
		"algorithm=SHA1&digits=6&issuer=Example.com&period=2"

	require.Equal(t, expectURI, uri)

	qrCode, err := key.QRCode(FixLevelDefault)
	require.NoError(t, err,
		"failed to generate QR code during test setup")

	// Generate PNG image via method
	pngImg1, err := qrCode.PNG(100, 100)
	require.NoError(t, err,
		"failed to generate PNG image from method during test setup")

	// Generate PNG image via test function
	pngImg2 := genPNG(t, uri, 100, 100)

	// Compare images
	require.Equal(t, pngImg1, pngImg2,
		"the generated PNG images should be the same")

	// Validate passcode in-time
	passcode, err := key.PassCode()
	require.NoError(t, err,
		"failed to generate passcode during test")

	ok := key.Validate(passcode)
	require.True(t, ok,
		"the passcode should be valid")
}

func TestQRCode_PNG_empty_uri(t *testing.T) {
	t.Parallel()

	qr := QRCode{
		URI:   URI(""),
		Level: FixLevelDefault,
	}

	img, err := qr.PNG(100, 100)

	require.Error(t, err,
		"empty URI should return error")
	require.Contains(t, err.Error(),
		"failed to encode URI to QR code: empty URI")
	require.Nil(t, img,
		"it should be nil on error")
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

	require.Error(t, err,
		"failed to encode QR code to PNG should return error")
	require.Contains(t, err.Error(),
		"failed to encode QR code image to PNG")
	require.Contains(t, err.Error(),
		"forced error")
	require.Nil(t, img,
		"it should be nil on error")
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

	require.Error(t, err,
		"failed to scale QR code should return error")
	require.Contains(t, err.Error(),
		"failed to scale QR code")
	require.Contains(t, err.Error(),
		"can not scale barcode to an image smaller than 49x49")
	require.Nil(t, img,
		"it should be nil on error")
}

// ----------------------------------------------------------------------------
//  Image Validation Tests
// ----------------------------------------------------------------------------
//  These tests validate that the generated QR codes are readable and contain
//  the correct data.
//  For scanning the generated QR code images we use the
//  `github.com/makiuchi-d/gozxing/qrcode` package, which is a Go port of the
//  ZXing library. It provides robust QR code decoding capabilities and is
//  actively maintained.

// TestQRCode_Validation validates that the generated QR code can be decoded
// and contains the correct TOTP URI.
func TestQRCode_Validation(t *testing.T) {
	t.Parallel()

	// Test URI for validation
	inputURI := "otpauth://totp/Example.com:alice@example.com?" +
		"algorithm=SHA1&digits=6&issuer=Example.com&period=30&" +
		"secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	key, err := GenerateKeyURI(inputURI)
	require.NoError(t, err,
		"failed to generate key from URI")

	// Generate QR code using our implementation
	qrCode, err := key.QRCode(FixLevelDefault)
	require.NoError(t, err,
		"failed to generate QR code")

	pngImg, err := qrCode.PNG(200, 200)
	require.NoError(t, err,
		"failed to generate PNG image")

	// Validate the QR code is readable and contains correct data
	decodedURI := decodeQRCodeWithGozxing(t, pngImg)
	require.Equal(t, key.URI(), decodedURI,
		"decoded URI should match the original TOTP URI")

	// Additional validation: ensure the decoded URI is a valid TOTP URI
	decodedKey, err := GenerateKeyURI(decodedURI)

	require.NoError(t, err,
		"decoded URI should be a valid TOTP URI")
	require.Equal(t, key.Secret.Base32(), decodedKey.Secret.Base32(),
		"secrets should match")
	require.Equal(t, key.Options.Issuer, decodedKey.Options.Issuer,
		"issuers should match")
	require.Equal(t, key.Options.AccountName, decodedKey.Options.AccountName,
		"account names should match")
}

// TestQRCode_Validation_DifferentSizes validates QR codes at various sizes.
func TestQRCode_Validation_DifferentSizes(t *testing.T) {
	t.Parallel()

	key, err := GenerateKey("Test Issuer", "test@example.com")
	require.NoError(t, err,
		"failed to generate key")

	sizes := []int{100, 200, 300, 500}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%dx%d", size, size), func(t *testing.T) {
			t.Parallel()

			qrCode, err := key.QRCode(FixLevelDefault)
			require.NoError(t, err,
				"failed to generate QR code")

			pngImg, err := qrCode.PNG(size, size)
			require.NoError(t, err,
				"failed to generate PNG at size %dx%d", size, size)

			// Validate the QR code is readable
			decodedURI := decodeQRCodeWithGozxing(t, pngImg)
			require.Equal(t, key.URI(), decodedURI,
				"decoded URI should match original at size %dx%d", size, size)
		})
	}
}

// TestQRCode_Validation_DifferentFixLevels validates QR codes with different
// error correction levels.
func TestQRCode_Validation_DifferentFixLevels(t *testing.T) {
	t.Parallel()

	key, err := GenerateKey("Test Issuer", "test@example.com")
	require.NoError(t, err,
		"failed to generate key")

	fixLevels := []FixLevel{FixLevel7, FixLevel15, FixLevel25, FixLevel30}
	fixLevelNames := []string{"FixLevel7", "FixLevel15", "FixLevel25", "FixLevel30"}

	for index, level := range fixLevels {
		t.Run(fixLevelNames[index], func(t *testing.T) {
			t.Parallel()

			qrCode, err := key.QRCode(level)
			require.NoError(t, err,
				"failed to generate QR code with %s", fixLevelNames[index])

			pngImg, err := qrCode.PNG(200, 200)
			require.NoError(t, err,
				"failed to generate PNG with %s", fixLevelNames[index])

			// Validate the QR code is readable
			decodedURI := decodeQRCodeWithGozxing(t, pngImg)
			require.Equal(t, key.URI(), decodedURI,
				"decoded URI should match original with %s", fixLevelNames[index])
		})
	}
}

// TestQRCode_Validation_ComplexURI tests QR code validation with complex URIs containing special characters.
func TestQRCode_Validation_ComplexURI(t *testing.T) {
	t.Parallel()

	// Test with special characters and longer content
	key, err := GenerateKey("Example Corp & Co.", "user+test@example-domain.com",
		WithAlgorithm(Algorithm("SHA256")),
		WithDigits(DigitsEight),
		WithPeriod(60),
	)

	require.NoError(t, err,
		"failed to generate key with complex parameters")

	qrCode, err := key.QRCode(FixLevel15) // Use lower error correction for better density
	require.NoError(t, err,
		"failed to generate QR code")

	pngImg, err := qrCode.PNG(400, 400) // Larger size for complex content
	require.NoError(t, err,
		"failed to generate PNG image")

	// Validate the complex QR code is readable
	decodedURI := decodeQRCodeWithGozxing(t, pngImg)
	require.Equal(t, key.URI(), decodedURI,
		"decoded complex URI should match original")
}

// ----------------------------------------------------------------------------
//  Helper functions
// ----------------------------------------------------------------------------

// genPNG generates a PNG image from the given URI. It is a naive implementation
// of QRCode.PNG() for testing purpose.
func genPNG(t *testing.T, uri string, width, height int) []byte {
	t.Helper()

	qrCode, err := qr.Encode(uri, FixLevel15.qrFixLevel(), qr.Auto)
	require.NoError(t, err,
		"failed to encode URI to QR code during test preparation")

	qrCode, err = barcode.Scale(qrCode, width, height)
	require.NoError(t, err,
		"failed to scale QR code during test preparation")

	var buf bytes.Buffer

	err = png.Encode(&buf, qrCode)
	require.NoError(t, err,
		"failed to encode QR code image to PNG during test preparation")

	return buf.Bytes()
}

// decodeQRCodeWithGozxing decodes a QR code PNG image using gozxing library and
// returns the contained text.
func decodeQRCodeWithGozxing(t *testing.T, pngData []byte) string {
	t.Helper()

	// Decode PNG image
	img, err := png.Decode(bytes.NewReader(pngData))
	require.NoError(t, err,
		"failed to decode PNG image during test preparation")

	// Create binary bitmap from image
	bitmap, err := gozxing.NewBinaryBitmapFromImage(img)
	require.NoError(t, err,
		"failed to create binary bitmap from image during test preparation")

	// Create QR code reader
	reader := qrcode.NewQRCodeReader()

	// Try decoding with different hint configurations for better reliability
	hintConfigs := []map[gozxing.DecodeHintType]interface{}{
		// First try without hints (default behavior)
		nil,
		// Try with character set hint
		{gozxing.DecodeHintType_CHARACTER_SET: "UTF-8"},
		// Try with pure barcode hint (assumes clean image)
		{gozxing.DecodeHintType_PURE_BARCODE: true},
		// Try with both hints
		{
			gozxing.DecodeHintType_CHARACTER_SET: "UTF-8",
			gozxing.DecodeHintType_PURE_BARCODE:  true,
		},
	}

	var lastErr error

	for attempt, hints := range hintConfigs {
		result, err := reader.Decode(bitmap, hints)
		if err == nil && result != nil && result.GetText() != "" {
			// Success! Return the decoded text
			return result.GetText()
		}

		lastErr = err

		// Log attempt for debugging (only in verbose mode)
		if testing.Verbose() {
			t.Logf("Decode attempt %d failed: %v", attempt+1, err)
		}
	}

	// If all attempts failed, fail the test with the last error
	require.NoError(t, lastErr,
		"failed to decode QR code from image after trying multiple hint configurations")

	return ""
}
