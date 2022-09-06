package totp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
//  Data Providers
// ----------------------------------------------------------------------------

//nolint:gochecknoglobals // allow global variables during tests
var badURIs = []struct {
	uri    string // Bad URI
	msgErr string // Message to be contained in the error
}{
	{
		"ipfs://totp/Example.com:alice@example.com?algorithm=SHA1&" +
			"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3",
		"invalid scheme",
	},
	{
		"otpauth://hotp/Example.com:alice@example.com?algorithm=SHA1&" +
			"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3",
		"invalid host",
	},
	{
		"otpauth://totp/alice@example.com?algorithm=SHA1&" +
			"digits=12&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3",
		"missing issuer or issuer is not set correctly",
	},
	{
		"otpauth://totp/Example.com:?algorithm=SHA1&" +
			"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3",
		"missing account name",
	},
	{
		"otpauth://totp/Example.com:alice@example.com?" +
			"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3",
		"missing algorithm",
	},
	{
		"otpauth://totp/Example.com:alice@example.com?algorithm=BLAKE3&" +
			"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3",
		"unsupported algorithm",
	},
	{
		"otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
			"issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3",
		"missing digits or zero digits set",
	},
	{
		"otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
			"digits=0&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3",
		"missing digits or zero digits set",
	},
	{
		"otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
			"digits=12&issuer=Example.com&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3",
		"missing period or zero period set",
	},
	{
		"otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
			"digits=12&issuer=Example.com&period=0&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3",
		"missing period or zero period set",
	},
	{
		"otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
			"digits=12&issuer=Example.com&period=60",
		"missing secret",
	},
	{
		"otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
			"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYW",
		"secret is too short. it should be at least 16 bytes",
	},
}

// ----------------------------------------------------------------------------
//  URI (General)
// ----------------------------------------------------------------------------

func TestURI_malformed_uri(t *testing.T) {
	t.Parallel()

	// Create a malformed URI which includes control characters
	const CTL = rune(0x7f)
	badURI := "this is a bad URI" + string(CTL)

	// Create URI object
	uri := URI(badURI)

	// Check should be error
	err := uri.Check()
	require.Error(t, err, "the Check() should return an error when malformed URI is given")

	// Methods should return empty string as well
	for _, test := range []struct {
		function func() string
		name     string
	}{
		{name: "Scheme", function: uri.Scheme},
		{name: "Host", function: uri.Host},
		{name: "Issuer", function: uri.Issuer},
		{name: "AccountName", function: uri.AccountName},
		{name: "Secret", function: uri.Secret().String},
		{name: "Algorithm", function: uri.Algorithm},
		{name: "IssuerFromPath", function: uri.IssuerFromPath},
	} {
		got := test.function()

		require.Empty(t, got, "it should be empty. function: %s", test.name)
	}

	require.Zero(t, uri.Digits(), "the Digits() should be zero on malformed URI")
	require.Zero(t, uri.Period(), "the Period() should be zero on malformed URI")
}

// ----------------------------------------------------------------------------
//  URI.AccountName()
// ----------------------------------------------------------------------------

func TestURI_AccountName_name_in_label_with_no_colon(t *testing.T) {
	t.Parallel()

	uri := NewURI("otpauth://totp/example.com?algorithm=SHA1")

	require.Empty(t, uri.Issuer(), "issuer should be empty")
	require.Equal(t, "example.com", uri.AccountName(), "label without colon should treat as account name")
}

// ----------------------------------------------------------------------------
//  URI.Check()
// ----------------------------------------------------------------------------

func TestURI_Check_error_msg(t *testing.T) {
	t.Parallel()

	for i, tt := range badURIs {
		uri := URI(tt.uri)    // Cast the string to URI type
		result := uri.Check() // Check the URI

		require.Error(t, result, "badURIs[%v] URI: %v", i, tt.uri)
		require.Contains(t, result.Error(), tt.msgErr)
	}
}

// ----------------------------------------------------------------------------
//  URI.Issuer()
// ----------------------------------------------------------------------------

func TestURI_Issuer_goledn(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		uri    string
		issuer string
		msg    string
	}{
		{"otpauth://totp/Example.com:", "Example.com", "label following colon should treat as issuer"},
		{"otpauth://totp/alice@example.com?foo=bar", "", "missing colon should treat as account name"},
		{"otpauth://totp/alice@example.com?issuer=Example.org", "Example.org", "issuer in query should be used"},
		{"otpauth://totp/:?issuer=Example.org", "Example.org", "issuer in query should be used"},
	} {
		uri := URI(test.uri)

		require.Equal(t, test.issuer, uri.Issuer(), "%v; uri: %v", test.msg, test.uri)
	}
}

func TestURI_Issuer_not_match_label_and_query(t *testing.T) {
	t.Parallel()

	// Example.org vs Example.com
	origin := "otpauth://totp/Example.org:alice@example.com?algorithm=SHA1&" +
		"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	uri := NewURI(origin)

	require.Empty(t, uri.Issuer(), "unmatched issuer between label and query should be empty")
}

// ----------------------------------------------------------------------------
//  URI.Secret()
// ----------------------------------------------------------------------------

func TestURI_Secret_bad_encoding(t *testing.T) {
	t.Parallel()

	//nolint:lll // allow long line
	origin := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&digits=6&issuer=Example.com&period=30&secret='BAD ENCODING'"
	uri := URI(origin)

	secret := uri.Secret()

	require.Nil(t, secret, "got %#v; want nil", secret)
}
