package totp

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// ----------------------------------------------------------------------------
//  Type: URI
// ----------------------------------------------------------------------------

// URI is a string that holds the TOTP URI.
//
// All methods are calculated each time they are called. Therefore, it is
// recommended to store them.
// Note also that the values are not validated. For example, `Digits()` method
// may return any value.
type URI string

// ----------------------------------------------------------------------------
//  Constructiors
// ----------------------------------------------------------------------------

// NewURI returns a new URI object. It simply returns the casted string as a
// URI object. To validate if the URI is correctly formatted, use the Check()
// method.
func NewURI(uri string) URI {
	return URI(uri)
}

// ----------------------------------------------------------------------------
//  Methods
// ----------------------------------------------------------------------------

// AccountName returns the account name from the URI.
func (u URI) AccountName() string {
	path := strings.TrimPrefix(u.Path(), "/")
	if path == "" {
		return ""
	}

	index := strings.Index(path, ":")

	if index == -1 {
		return path
	}

	return path[index+1:]
}

// Algorithm returns the algorithm from the URI.
func (u URI) Algorithm() string {
	parsedURI, err := url.Parse(string(u))
	if err != nil {
		return ""
	}

	return parsedURI.Query().Get("algorithm")
}

// Check returns true if the URI is correctly formatted and required fields are
// set.
//
//nolint:cyclop // cyclomatic complexity is 11 but it's fine
func (u URI) Check() error {
	// Check required fields
	switch {
	case u.Scheme() != "otpauth":
		return errors.New("invalid scheme. it always should be `otpauth`")
	case u.Host() != "totp":
		return errors.New("invalid host. it always should be `totp`")
	case u.Issuer() == "":
		return errors.New("missing issuer or issuer is not set correctly")
	case u.AccountName() == "":
		return errors.New("missing account name")
	case u.Secret() == nil:
		return errors.New("missing secret")
	case u.Algorithm() == "":
		return errors.New("missing algorithm")
	case u.Digits() == uint(0):
		return errors.New("missing digits or zero digits set")
	case u.Period() == uint(0):
		return errors.New("missing period or zero period set")
	}

	// Check supported algorithms
	if algo := Algorithm(u.Algorithm()); !algo.IsSupported() {
		return errors.Errorf("unsupported algorithm: %s", algo)
	}

	// Check length of secret. According to the RFC4226, the secret MUST be at
	// least 128 bits = 16 bytes.
	// See:
	//   https://www.rfc-editor.org/rfc/rfc4226#section-4
	minLenBytes := 16

	if len(u.Secret().Bytes()) < minLenBytes {
		return errors.New("secret is too short. it should be at least 16 bytes")
	}

	return nil
}

// Digits returns the number of digits a TOTP hash should have from the URI query.
func (u URI) Digits() uint {
	parsedURI, err := url.Parse(string(u))
	if err != nil {
		return 0
	}

	digitStr := parsedURI.Query().Get("digits")
	base10 := 10
	bitSize := 64

	if digitUint64, err := strconv.ParseUint(digitStr, base10, bitSize); err == nil {
		return uint(digitUint64)
	}

	return 0
}

// Host returns the host name from the URI. This should be `totp`.
func (u URI) Host() string {
	parsedURI, err := url.Parse(string(u))
	if err != nil {
		return ""
	}

	return parsedURI.Host
}

// Issuer returns the issuer from the URI. Similar to IssuerFromPath() but returns
// the issuer from the query string instead of the path.
func (u URI) Issuer() string {
	parsedURI, err := url.Parse(string(u))
	if err != nil {
		return ""
	}

	issuerPath := u.IssuerFromPath()
	issuerQuery := parsedURI.Query().Get("issuer")

	// Search issuer from the query string
	switch {
	case issuerQuery != "" && issuerPath == "":
		return issuerQuery
	case issuerQuery == "" && issuerPath != "":
		return issuerPath
	case issuerQuery == issuerPath:
		return issuerQuery
	}

	return ""
}

// IssuerFromPath returns the issuer from the URI. Similar to Issuer() but returns
// the issuer from the path instead of the query string.
func (u URI) IssuerFromPath() string {
	path := strings.TrimPrefix(u.Path(), "/")
	if path == "" {
		return ""
	}

	index := strings.Index(path, ":")

	if index == -1 {
		return ""
	}

	return path[:index]
}

// Path returns the path from the URI. Which is used as a "label" for the TOTP.
// See:
//
//	https://github.com/google/google-authenticator/wiki/Key-Uri-Format#label
func (u URI) Path() string {
	parsedURI, err := url.Parse(string(u))
	if err != nil {
		return ""
	}

	return parsedURI.Path
}

// Period returns the number of seconds a TOTP hash is valid for from the URI.
// If the period is not set or the URL is invalid, it returns 0.
func (u URI) Period() uint {
	parsedURI, err := url.Parse(string(u))
	if err != nil {
		return 0
	}

	periodStr := parsedURI.Query().Get("period")
	base10 := 10
	bitSize := 64

	if periodUint64, err := strconv.ParseUint(periodStr, base10, bitSize); err == nil {
		return uint(periodUint64)
	}

	return 0
}

// Scheme returns the scheme/protocol from the URI. This should be `otpauth`.
func (u URI) Scheme() string {
	parsedURI, err := url.Parse(string(u))
	if err != nil {
		return ""
	}

	return parsedURI.Scheme
}

// Secret returns the secret key from the URI as a Secret object.
func (u URI) Secret() Secret {
	parsedURI, err := url.Parse(string(u))
	if err != nil {
		return nil
	}

	secret, err := NewSecretBase32(parsedURI.Query().Get("secret"))
	if err != nil || secret.String() == "" {
		return nil
	}

	return secret
}

// String is an implementation of the Stringer interface.
// It just returns the raw URI.
func (u URI) String() string {
	return string(u)
}
