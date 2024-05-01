package totp

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/pem"
	"testing"
	"time"

	"github.com/pkg/errors"
	origOtp "github.com/pquerna/otp"
	origTotp "github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
//  GenerateKey()
// ----------------------------------------------------------------------------

func TestGenerateKey_bad_option(t *testing.T) {
	t.Parallel()

	key, err := GenerateKey(
		"Example.com",
		"alice@example.com",
		WithAlgorithm(Algorithm("BADALGO")),
	)

	require.Error(t, err,
		"missing issuer should return error")
	require.Nil(t, key,
		"returned key should be nil on error")
	require.Contains(t, err.Error(),
		"failed to apply custom options: unsupported algorithm: BADALGO")
}

func TestGenerateKey_missing_issuer(t *testing.T) {
	t.Parallel()

	key, err := GenerateKey("", "alice@example.com")

	require.Error(t, err,
		"missing issuer should return error")
	require.Nil(t, key,
		"returned key should be nil on error")
	require.Contains(t, err.Error(),
		"failed to create options during key generation: issuer and accountName are required")
}

func TestGenerateKeyCustom_curve_mismatch(t *testing.T) {
	t.Parallel()

	// Curve25519
	curveA := ecdh.X25519()

	privKeyA, err := curveA.GenerateKey(rand.Reader)
	require.NoError(t, err, "failed to generate ECDH private key for A during test")

	// P-384
	curveB := ecdh.P384()

	privKeyB, err := curveB.GenerateKey(rand.Reader)
	require.NoError(t, err, "failed to generate ECDH private key for B during test")

	pubKeyB := privKeyB.PublicKey()

	key, err := GenerateKey("name issuer", "account name",
		WithECDH(privKeyA, pubKeyB, "my context"),
	)

	require.Error(t, err,
		"mismatching curve type should return error. A: %v, B: %v", privKeyA.Curve(), pubKeyB.Curve())
	require.Contains(t, err.Error(), "failed to generate ECDH shared secret",
		"error message should contain the error reason")
	require.Contains(t, err.Error(), "private key and public key curves do not match",
		"error message should contain the underlying error reason")
	require.Nil(t, key,
		"returned key should be nil on error")
}

// ----------------------------------------------------------------------------
//  GenerateKeyCustom()
// ----------------------------------------------------------------------------

//nolint:paralleltest // disable parallel test due to monkey patching during test
func TestGenerateKeyCustom_wrong_digits(t *testing.T) {
	// Backup and defer restore
	oldTotpGenerate := totpGenerate
	defer func() {
		totpGenerate = oldTotpGenerate
	}()

	// Mock totpGenerate to force return malformed uri
	totpGenerate = func(_ origTotp.GenerateOpts) (*origOtp.Key, error) {
		// URI with bad secret format
		//nolint:lll // ignore long line length due to URI
		url := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&digits=6&issuer=Example.com&period=30&secret=BADSECRET$$"

		return origOtp.NewKeyFromURL(url)
	}

	//nolint:exhaustruct // allow missing fields
	opt := Options{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
	}

	key, err := GenerateKeyCustom(opt)

	require.Error(t, err, "bad encoding of secret should return error")
	require.Nil(t, key, "it should be nil on error")
	require.Contains(t, err.Error(), "failed to create secret")
	require.Contains(t, err.Error(), "failed to decode base32 string")
}

// ----------------------------------------------------------------------------
//  GenerateKeyPEM() : Deprecated function. This test will be removed in v1.0.0
// ----------------------------------------------------------------------------

func TestGenerateKeyPEM(t *testing.T) {
	t.Parallel()

	pemData := `
-----BEGIN TOTP SECRET KEY-----
Account Name: alice@example.com
Algorithm: SHA1
Digits: 8
Issuer: Example.com
Period: 30
Secret Size: 64
Skew: 0

gX7ff3VlT4sCakCjQH69ZQxTbzs=
-----END TOTP SECRET KEY-----`

	key, err := GenerateKeyPEM(pemData)

	require.NoError(t, err, "PEM file with TOTP key should not return error")
	assert.Equal(t, "alice@example.com", key.Options.AccountName)
	assert.Equal(t, "Example.com", key.Options.Issuer)
	assert.Equal(t, "8", key.Options.Digits.String())
}

// ----------------------------------------------------------------------------
//  GenKeyFromPEM()
// ----------------------------------------------------------------------------

func TestGenKeyFromPEM_bad_pem_file(t *testing.T) {
	t.Parallel()

	pemData := `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlRuRnThUjU8/prwYxbty
WPT9pURI3lbsKMiB6Fn/VHOKE13p4D8xgOCADpdRagdT6n4etr9atzDKUSvpMtR3
CP5noNc97WiNCggBjVWhs7szEe8ugyqF23XwpHQ6uV1LKH50m92MbOWfCtjU9p/x
qhNpQQ1AZhqNy5Gevap5k8XzRmjSldNAFZMY7Yv3Gi+nyCwGwpVtBUwhuLzgNFK/
yDtw2WcWmUU7NuC8Q6MWvPebxVtCfVp/iQU6q60yyt6aGOBkhAX0LpKAEhKidixY
nP9PNVBvxgu3XZ4P36gZV6+ummKdBVnc3NqwBLu5+CcdRdusmHPHd5pHf4/38Z3/
6qU2a/fPvWzceVTEgZ47QjFMTCTmCwNt29cvi7zZeQzjtwQgn4ipN9NibRH/Ax/q
TbIzHfrJ1xa2RteWSdFjwtxi9C20HUkjXSeI4YlzQMH0fPX6KCE7aVePTOnB69I/
a9/q96DiXZajwlpq3wFctrs1oXqBp5DVrCIj8hU2wNgB7LtQ1mCtsYz//heai0K9
PhE4X6hiE0YmeAZjR0uHl8M/5aW9xCoJ72+12kKpWAa0SFRWLy6FejNYCYpkupVJ
yecLk/4L1W0l6jQQZnWErXZYe0PNFcmwGXy1Rep83kfBRNKRy5tvocalLlwXLdUk
AIU+2GKjyT3iMuzZxxFxPFMCAwEAAQ==
-----END PUBLIC KEY-----
`

	key, err := GenKeyFromPEM(pemData)

	require.Error(t, err, "PEM file without TOTP key should return error")
	require.Contains(t, err.Error(), "failed to decode PEM block containing TOTP secret key")
	require.Nil(t, key)
}

func TestGenKeyFromPEM_multiple_pem_keys(t *testing.T) {
	t.Parallel()

	pemData := `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlRuRnThUjU8/prwYxbty
WPT9pURI3lbsKMiB6Fn/VHOKE13p4D8xgOCADpdRagdT6n4etr9atzDKUSvpMtR3
CP5noNc97WiNCggBjVWhs7szEe8ugyqF23XwpHQ6uV1LKH50m92MbOWfCtjU9p/x
qhNpQQ1AZhqNy5Gevap5k8XzRmjSldNAFZMY7Yv3Gi+nyCwGwpVtBUwhuLzgNFK/
yDtw2WcWmUU7NuC8Q6MWvPebxVtCfVp/iQU6q60yyt6aGOBkhAX0LpKAEhKidixY
nP9PNVBvxgu3XZ4P36gZV6+ummKdBVnc3NqwBLu5+CcdRdusmHPHd5pHf4/38Z3/
6qU2a/fPvWzceVTEgZ47QjFMTCTmCwNt29cvi7zZeQzjtwQgn4ipN9NibRH/Ax/q
TbIzHfrJ1xa2RteWSdFjwtxi9C20HUkjXSeI4YlzQMH0fPX6KCE7aVePTOnB69I/
a9/q96DiXZajwlpq3wFctrs1oXqBp5DVrCIj8hU2wNgB7LtQ1mCtsYz//heai0K9
PhE4X6hiE0YmeAZjR0uHl8M/5aW9xCoJ72+12kKpWAa0SFRWLy6FejNYCYpkupVJ
yecLk/4L1W0l6jQQZnWErXZYe0PNFcmwGXy1Rep83kfBRNKRy5tvocalLlwXLdUk
AIU+2GKjyT3iMuzZxxFxPFMCAwEAAQ==
-----END PUBLIC KEY-----
-----BEGIN TOTP SECRET KEY-----
Account Name: alice@example.com
Algorithm: SHA1
Digits: 6
Issuer: Example.com
Period: 30
Secret Size: 20
Skew: 0

gX7ff3VlT4sCakCjQH69ZQxTbzs=
-----END TOTP SECRET KEY-----`

	key, err := GenKeyFromPEM(pemData)

	require.NoError(t, err, "multiple PEM with valid key should not return error")
	require.NotNil(t, key)

	assert.Equal(t, "alice@example.com", key.Options.AccountName)
	assert.Equal(t, Algorithm("SHA1"), key.Options.Algorithm)
	assert.Equal(t, DigitsSix, key.Options.Digits)
	assert.Equal(t, "Example.com", key.Options.Issuer)
	assert.Equal(t, uint(30), key.Options.Period)
	assert.Equal(t, uint(20), key.Options.SecretSize)
	assert.Equal(t, uint(0), key.Options.Skew)
	assert.Equal(t, "QF7N673VMVHYWATKICRUA7V5MUGFG3Z3", key.Secret.Base32())
}

// ----------------------------------------------------------------------------
//  GenerateKeyURI()
// ----------------------------------------------------------------------------

//nolint:paralleltest // disable parallel test due to monkey patching during test
func TestGenerateKeyURI_error_msg(t *testing.T) {
	key1, err := GenerateKeyURI("")

	require.Error(t, err, "malformed URI should return error")
	require.Nil(t, key1)
	require.Contains(t, err.Error(), "failed to create URI object from the given URI")

	// Backup and defer restore
	oldTotpGenerate := totpGenerate
	defer func() {
		totpGenerate = oldTotpGenerate
	}()

	// Mock totpGenerate to force return error
	totpGenerate = func(_ origTotp.GenerateOpts) (*origOtp.Key, error) {
		return nil, errors.New("forced error")
	}

	key2, err := GenerateKeyURI("otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3")

	require.Error(t, err, "missing issuer and account name should return error")
	require.Nil(t, key2)
	require.Contains(t, err.Error(), "failed to generate key")
}

// ----------------------------------------------------------------------------
//  Key.QRCode()
// ----------------------------------------------------------------------------

func TestKey_QRCode_bad_fix_level(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct // missing fields are not required for this test
	key := Key{}

	imgQRCode, err := key.QRCode(FixLevel(100))

	require.Error(t, err, "unsupported fix level should return error")
	require.Contains(t, err.Error(), "unsupported fix level: 100")
	require.Nil(t, imgQRCode)
}

// ----------------------------------------------------------------------------
//  Key.PEM()
// ----------------------------------------------------------------------------

//nolint:paralleltest // disable parallel test due to monkey patching during test
func TestKey_PEM(t *testing.T) {
	// Backup and defer restore
	oldPemEncodeToMemory := pemEncodeToMemory
	defer func() {
		pemEncodeToMemory = oldPemEncodeToMemory
	}()

	// Mock pemEncodeToMemory to force return nil as an error
	pemEncodeToMemory = func(_ *pem.Block) []byte {
		return nil
	}

	//nolint:exhaustruct // disable exhaust struct linter due to test
	key := Key{}

	pemOut, err := key.PEM()

	require.Error(t, err, "missing key should return error")
	require.Contains(t, err.Error(), "failed to encode key to PEM")
	require.Empty(t, pemOut)
}

// ============================================================================
//  Tests for fixed issues
// ============================================================================
//  These tests reproduce the issues and should pass if the issue is fixed.

// Issue #42.
// If `Period` is set short with `Skew=0`, the passcode validation often fails.
func TestKey_skew_as_one(t *testing.T) {
	// Backup and defer restore
	oldTimeNow := timeNow
	defer func() {
		timeNow = oldTimeNow
	}()

	key, err := GenerateKey("dummy issuer", "dummy account")
	require.NoError(t, err, "failed to generate TOTP key during test setup")

	key.Options.Period = 3 // 3 seconds
	//key.Options.Skew = 1   // ± 1 period of tolerance

	getCode := func(t *testing.T, key *Key) string {
		t.Helper()

		// Monkey patch timeNow
		timeNow = func() time.Time {
			return time.Now()
		}

		passCode, err := key.PassCode()
		require.NoError(t, err, "failed to generate passcode")

		return passCode
	}

	validateCode := func(t *testing.T, key *Key, passCode string) bool {
		t.Helper()

		// Monkey patch timeNow
		timeNow = func() time.Time {
			return time.Now().Add(time.Second * 200)
		}

		// sleep for 2 sec. this causes error 60% of the time
		time.Sleep(time.Second * 2)

		return key.Validate(passCode)
	}

	numValid := 0
	numIterations := 10

	for i := 0; i < numIterations; i++ {
		passCode := getCode(t, key)
		ok := validateCode(t, key, passCode)

		if ok {
			numValid++
		}
	}

	expect := numIterations
	actual := numValid

	require.Equal(t, expect, actual,
		"not all generated passcodes are valid")
}
