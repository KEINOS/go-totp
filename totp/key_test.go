package totp

import (
	"testing"

	"github.com/pkg/errors"
	origOtp "github.com/pquerna/otp"
	origTotp "github.com/pquerna/otp/totp"
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
