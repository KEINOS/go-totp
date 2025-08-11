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

	badURI := "this is a bad URI" + string(CTL) // Add a control character to make it malformed
	uri := URI(badURI)                          // Create URI object

	// Check should be error
	err := uri.Check()
	require.Error(t, err,
		"the Check() should return an error when malformed URI is given")

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

		require.Empty(t, got,
			"it should be empty. function: %s", test.name)
	}

	require.Zero(t, uri.Digits(),
		"the Digits() should be zero on malformed URI")
	require.Zero(t, uri.Period(),
		"the Period() should be zero on malformed URI")
}

// ----------------------------------------------------------------------------
//  URI.AccountName()
// ----------------------------------------------------------------------------

func TestURI_AccountName_name_in_label_with_no_colon(t *testing.T) {
	t.Parallel()

	uri := NewURI("otpauth://totp/example.com?algorithm=SHA1")

	require.Empty(t, uri.Issuer(),
		"issuer should be empty")
	require.Equal(t, "example.com", uri.AccountName(),
		"label without colon should treat as account name")
}

// ----------------------------------------------------------------------------
//  URI.Check()
// ----------------------------------------------------------------------------

func TestURI_Check_error_msg(t *testing.T) {
	t.Parallel()

	for index, badURI := range badURIs {
		uri := URI(badURI.uri) // Cast the string to URI type
		result := uri.Check()  // Check the URI

		require.Error(t, result,
			"badURIs[%v] URI: %v", index, badURI.uri)
		require.Contains(t, result.Error(), badURI.msgErr,
			"unexpected error message")
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
		{"otpauth://totp/Example.com:?issuer=Example.com", "Example.com",
			"issuer should be parsed when both label and query match"},
		{"otpauth://totp/Example.com:", "",
			"label following colon should be invalid if query is missing"},
		{"otpauth://totp/alice@example.com?foo=bar", "",
			"missing colon should treat as account name"},
		{"otpauth://totp/alice@example.com?issuer=Example.org",
			"", "issuer in query should be invalid if label is missing"},
		{"otpauth://totp/:?issuer=Example.org", "",
			"issuer in query should be invalid if label is empty"},
	} {
		uri := URI(test.uri)
		expect := test.issuer
		actual := uri.Issuer()

		require.Equal(t, expect, actual,
			"%v; uri: %v", test.msg, test.uri)
	}
}

func TestURI_Issuer_not_match_label_and_query(t *testing.T) {
	t.Parallel()

	// Example.org vs Example.com
	origin := "otpauth://totp/Example.org:alice@example.com?algorithm=SHA1&" +
		"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	uri := NewURI(origin)

	require.Empty(t, uri.Issuer(),
		"unmatched issuer between label and query should be empty")
}

// ----------------------------------------------------------------------------
//  URI.Secret()
// ----------------------------------------------------------------------------

func TestURI_Secret_bad_encoding(t *testing.T) {
	t.Parallel()

	origin := "otpauth://totp/Example.com:alice@example.com?" +
		"algorithm=SHA1&" + "digits=6&" + "issuer=Example.com&" + "period=30&" +
		"secret='BAD ENCODING'"

	uri := URI(origin)
	secret := uri.Secret()

	require.Nil(t, secret,
		"got %#v; want nil", secret)
}

// ----------------------------------------------------------------------------
//  URI.Type()
// ----------------------------------------------------------------------------

func TestURI_Type_golden(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name   string
		uri    string
		expect string
	}{
		{
			name: "label issuer and account in path",
			uri: "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&digits=6&" +
				"issuer=Example.com&period=30&secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
			expect: "totp",
		},
		{
			name: "issuer only in query",
			uri: "otpauth://totp/:alice@example.com?algorithm=SHA1&digits=6&" +
				"issuer=Example.com&period=30&secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
			expect: "totp",
		},
		{
			name: "hotp basic",
			uri: "otpauth://hotp/Example.com:alice@example.com?algorithm=SHA1&digits=6&" +
				"issuer=Example.com&period=30&secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
			expect: "hotp",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			u := NewURI(testCase.uri)
			require.NotEmpty(t, u.Type(),
				"Type() should not be empty for otpauth URIs")

			expect := testCase.expect
			actual := u.Type()

			require.Equal(t, expect, actual,
				"Type() should return the correct value for otpauth URIs")
		})
	}
}

func TestURI_Type_malformed(t *testing.T) {
	t.Parallel()

	// Malformed URI (includes control char)
	const CTL = rune(0x7f)

	for _, testCase := range []struct {
		name string
		uri  string
	}{
		{
			name: "wrong scheme",
			uri: "ipfs://totp/Example.com:alice@example.com?algorithm=SHA1&digits=6&" +
				"issuer=Example.com&period=30&secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
		},
		{
			name: "missing host",
			uri: "otpauth:///Example.com:alice@example.com?algorithm=SHA1&digits=6&" +
				"issuer=Example.com&period=30&secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
		},
		{
			name: "malformed uri",
			uri:  "this is not a uri" + string(CTL),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			u := NewURI(testCase.uri)
			require.Empty(t, u.Type(),
				"Type() should be empty on non-otpauth or malformed URIs")
		})
	}
}

// ----------------------------------------------------------------------------
//  URI.Label()
// ----------------------------------------------------------------------------

func TestURI_Label_golden(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name   string
		uri    string
		expect string
	}{
		{
			name:   "issuer and account in path",
			uri:    "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1",
			expect: "Example.com:alice@example.com",
		},
		{
			name: "escaped space in issuer",
			uri: "otpauth://totp/ACME%20Co:john.doe@email.com?algorithm=SHA1&" +
				"digits=6&issuer=ACME%20Co&period=30&secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
			expect: "ACME Co:john.doe@email.com",
		},
		{
			name:   "account only (no colon)",
			uri:    "otpauth://totp/alice@example.com?algorithm=SHA1",
			expect: "alice@example.com",
		},
		{
			name:   "empty label",
			uri:    "otpauth://totp/?algorithm=SHA1",
			expect: "",
		},
		{
			name:   "Provider1:Alice%20Smith",
			uri:    "otpauth://totp/Provider1:Alice%20Smith?secret=JBSWY3DPEHPK3PXP&issuer=Provider1",
			expect: "Provider1:Alice Smith",
		},
		{
			name:   "Big%20Corporation%3A%20alice%40bigco.com",
			uri:    "otpauth://totp/Big%20Corporation%3A%20alice%40bigco.com?secret=JBSWY3DPEHPK3PXP&issuer=Big%20Corporation",
			expect: "Big Corporation: alice@bigco.com",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			u := NewURI(testCase.uri)
			expect := testCase.expect
			actual := u.Label()

			require.Equal(t, expect, actual,
				"Label() should return unescaped label without leading slash")
		})
	}
}

func TestURI_Label_malformed(t *testing.T) {
	t.Parallel()

	const CTL = rune(0x7f)

	for _, testCase := range []struct {
		name string
		uri  string
	}{
		{
			name: "malformed uri (control char)",
			uri:  "this is not a uri" + string(CTL),
		},
		{
			name: "invalid percent-encoding in label",
			uri: "otpauth://totp/ACME%2GCo:john.doe@email.com?algorithm=SHA1&" +
				"digits=6&issuer=ACME%20Co&period=30&secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
		},
		{
			name: "trailing percent sign in label",
			uri:  "otpauth://totp/FOO%?algorithm=SHA1",
		},
		{
			name: "incomplete percent-encoding (one hex) in label",
			uri:  "otpauth://totp/FOO%A?algorithm=SHA1",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			u := NewURI(testCase.uri)

			require.Empty(t, u.Label(),
				"Label() should be empty on malformed URI or invalid percent-encoding")
		})
	}
}

// ----------------------------------------------------------------------------
//  URI.Parameters()
// ----------------------------------------------------------------------------

func TestURI_Parameters_golden(t *testing.T) {
	t.Parallel()

	// Reuse the constant from key tests
	totpURI := URI(testURIForSecretQueryFirst)

	// Alphabetical order (secret last)
	gotAlpha := totpURI.Parameters(false)
	wantAlpha := "algorithm=SHA256&digits=8&issuer=domain.com&period=45&" +
		"secret=DEOXGYTNWD3D6J3RNBEGCI2R45X3XO3X"
	require.Equal(t, wantAlpha, gotAlpha,
		"alphabetical query should match expected order")

	// Secret first
	gotSecretFirst := totpURI.Parameters(true)
	wantSecretFirst := "secret=DEOXGYTNWD3D6J3RNBEGCI2R45X3XO3X&" +
		"algorithm=SHA256&digits=8&issuer=domain.com&period=45"
	require.Equal(t, wantSecretFirst, gotSecretFirst,
		"secret-first query should match expected order")
}

func TestURI_Parameters_space_encoding(t *testing.T) {
	t.Parallel()

	// Expect space to be encoded as %20 (not '+')
	uri := NewURI("otpauth://totp/ACME%20Co:john@example.com?algorithm=SHA1&digits=6&" +
		"issuer=ACME%20Co&period=30&secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")

	got := uri.Parameters(false)

	require.Contains(t, got, "issuer=ACME%20Co",
		"space in parameter should be encoded as %20, not '+'")
	require.NotContains(t, got, "issuer=ACME+Co",
		"space in parameter should not be encoded as '+'")
}

func TestURI_Parameters_malformed(t *testing.T) {
	t.Parallel()

	const CTL = rune(0x7f)

	bad := URI("this is not a uri" + string(CTL))

	require.Empty(t, bad.Parameters(false),
		"malformed URIs should return empty parameters")
}

func TestURI_Parameters_empty_values(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name string
		uri  string
	}{
		{
			name: "no query section",
			uri:  "otpauth://totp/Example.com:alice@example.com",
		},
		{
			name: "empty query",
			uri:  "otpauth://totp/Example.com:alice@example.com?",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			u := NewURI(testCase.uri)

			require.Empty(t, u.Parameters(false),
				"Parameters(false) should be empty when no query params exist")
			require.Empty(t, u.Parameters(true),
				"Parameters(true) should be empty when no query params exist")
		})
	}
}
