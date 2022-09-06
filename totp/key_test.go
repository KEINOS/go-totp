package totp

import (
	"encoding/pem"
	"testing"

	"github.com/pkg/errors"
	origOtp "github.com/pquerna/otp"
	origTotp "github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
//  GenerateKey()
// ----------------------------------------------------------------------------

func TestGenerateKey_missing_issuer(t *testing.T) {
	t.Parallel()

	key, err := GenerateKey("", "alice@example.com")

	require.Error(t, err, "missing issuer should return error")
	require.Nil(t, key)
	require.Contains(t, err.Error(), "failed to generate key: Issuer must be set")
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
	totpGenerate = func(opts origTotp.GenerateOpts) (*origOtp.Key, error) {
		// URI with bad secret format
		//nolint:lll // ignore long line length due to URI
		url := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&digits=6&issuer=Example.com&period=30&secret=BADSECRET$$"
		//nolint:wrapcheck // ignore error wrap check
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
//  GenerateKeyPEM()
// ----------------------------------------------------------------------------

func TestGenerateKeyPEM_bad_pem_file(t *testing.T) {
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

	key, err := GenerateKeyPEM(pemData)

	require.Error(t, err, "PEM file without TOTP key should return error")
	require.Contains(t, err.Error(), "failed to decode PEM block containing TOTP secret key")
	require.Nil(t, key)
}

func TestGenerateKeyPEM_multiple_pem_keys(t *testing.T) {
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

	key, err := GenerateKeyPEM(pemData)

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
	totpGenerate = func(opts origTotp.GenerateOpts) (*origOtp.Key, error) {
		return nil, errors.New("forced error")
	}

	key2, err := GenerateKeyURI("otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3")

	require.Error(t, err, "missing issuer and account name should return error")
	require.Nil(t, key2)
	require.Contains(t, err.Error(), "failed to generate key")
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
	pemEncodeToMemory = func(b *pem.Block) []byte {
		return nil
	}

	//nolint:exhaustruct // disable exhaust struct linter due to test
	key := Key{}

	pemOut, err := key.PEM()

	require.Error(t, err, "missing key should return error")
	require.Contains(t, err.Error(), "failed to encode key to PEM")
	require.Empty(t, pemOut)
}
