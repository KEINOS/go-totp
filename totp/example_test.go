package totp_test

import (
	"fmt"
	"log"

	"github.com/KEINOS/go-totp/totp"
)

func Example() {
	// Generate a new secret key
	Issuer := "Example.com"
	AccountName := "alice@example.com"

	key, err := totp.GenerateKey(Issuer, AccountName)
	if err != nil {
		log.Fatal(err)
	}

	// Generate 6 digits passcode (valid for 30 seconds)
	passcode, err := key.PassCode()
	if err != nil {
		log.Fatal(err)
	}

	// Validate the passcode
	valid, err := key.Validate(passcode)
	if err != nil {
		log.Fatal(err)
	}

	if valid {
		fmt.Println("Passcode is valid")
	}

	// Output: Passcode is valid
}

func Example_advanced() {
	// Options to generate a new key. The secret will be generated randomly.
	opts := totp.Options{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
		Algorithm:   totp.Algorithm("SHA1"), // Choices are: MD5, SHA1, SHA256 and SHA512
		Period:      60,                     // Validity period in seconds
		SecretSize:  20,                     // Secret key size in bytes
		Skew:        0,                      // Number of periods before or after the current time to allow.
		Digits:      totp.Digits(8),         // Choices are: 6 and 8
	}

	// Generate a new secret key
	key, err := totp.GenerateKeyCustom(opts)
	if err != nil {
		log.Fatal(err)
	}

	// Generate 8 digits passcode that are valid for 60 seconds (see options above)
	passcode, err := key.PassCode()
	if err != nil {
		log.Fatal(err)
	}

	// Validate the passcode
	valid, err := key.Validate(passcode)
	if err != nil {
		log.Fatal(err)
	}

	if valid {
		fmt.Println("Passcode is valid")
	}

	// Output: Passcode is valid
}

// ----------------------------------------------------------------------------
//  Type: Algorithm
// ----------------------------------------------------------------------------

func ExampleAlgorithm() {
	// Create a new Algorithm object from a string. Choices are:
	//   MD5, SHA1, SHA256 and SHA512.
	algo, err := totp.NewAlgorithmStr("SHA512")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Algorithm:", algo.String())
	fmt.Println("Algorithm ID:", algo.ID())
	fmt.Printf("Type: %T\n", algo.OTPAlgorithm())

	// Output:
	// Algorithm: SHA512
	// Algorithm ID: 2
	// Type: otp.Algorithm
}

func ExampleAlgorithm_IsSupported() {
	// Cast a string to Algorithm type
	algo := totp.Algorithm("BLAKE3")

	// Check if the algorithm is supported
	if algo.IsSupported() {
		fmt.Println("Algorithm is supported")
	} else {
		fmt.Println("Algorithm is not supported")
	}

	// Output: Algorithm is not supported
}

// ----------------------------------------------------------------------------
//  Type: Digits
// ----------------------------------------------------------------------------

func ExampleDigits() {
	// Create a new Digits object from a number. Choices are:
	//   6 and 8.
	digits := totp.NewDigits(8)

	fmt.Println("Digits:", digits)
	fmt.Println("Digits ID:", digits.OTPDigits())

	// DigitsEight is equivalent to NewDigits(8)
	if totp.DigitsEight == totp.NewDigits(8) {
		fmt.Println("Digit 8", "OK")
	}

	// DigitsSix is equivalent to NewDigits(6)
	if totp.DigitsSix == totp.NewDigits(6) {
		fmt.Println("Digit 6", "OK")
	}

	// Output:
	// Digits: 8
	// Digits ID: 8
	// Digit 8 OK
	// Digit 6 OK
}

// ----------------------------------------------------------------------------
//  Function: GenerateKeyURI
// ----------------------------------------------------------------------------

func ExampleGenerateKeyURI() {
	origin := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	key, err := totp.GenerateKeyURI(origin)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Issuer:", key.Options.Issuer)
	fmt.Println("AccountName:", key.Options.AccountName)
	fmt.Println("Algorithm:", key.Options.Algorithm)
	fmt.Println("Digits:", key.Options.Digits)
	fmt.Println("Period:", key.Options.Period)
	fmt.Println("Secret Size:", key.Options.SecretSize)
	fmt.Println("Secret:", key.Secret.String())

	// Output:
	// Issuer: Example.com
	// AccountName: alice@example.com
	// Algorithm: SHA1
	// Digits: 12
	// Period: 60
	// Secret Size: 20
	// Secret: QF7N673VMVHYWATKICRUA7V5MUGFG3Z3
}

// ----------------------------------------------------------------------------
//  Type: Key
// ----------------------------------------------------------------------------

func ExampleKey() {
	// Generate a new secret key
	Issuer := "Example.com"
	AccountName := "alice@example.com"

	key, err := totp.GenerateKey(Issuer, AccountName)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Issuer:", key.Options.AccountName)
	fmt.Println("AccountName:", key.Options.AccountName)

	// Output:
	// Issuer: alice@example.com
	// AccountName: alice@example.com
}

// ----------------------------------------------------------------------------
//  Func: NewSecretBytes()
// ----------------------------------------------------------------------------

func ExampleNewSecretBytes() {
	data := []byte("some secret")

	// Generate a new Secret object from a byte slice.
	secret := totp.NewSecretBytes(data)

	fmt.Printf("Type: %T\n", secret)
	fmt.Printf("Value: %#v\n", secret)
	fmt.Println("Secret bytes:", secret.Bytes())
	fmt.Println("Secret string:", secret.String())
	fmt.Println("Secret Base32:", secret.Base32())
	fmt.Println("Secret Base62:", secret.Base62())

	// Output:
	// Type: totp.Secret
	// Value: totp.Secret{0x73, 0x6f, 0x6d, 0x65, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74}
	// Secret bytes: [115 111 109 101 32 115 101 99 114 101 116]
	// Secret string: ONXW2ZJAONSWG4TFOQ
	// Secret Base32: ONXW2ZJAONSWG4TFOQ
	// Secret Base62: bfF9D3ygDyVQZp2
}

// ----------------------------------------------------------------------------
//  Type: Options
// ----------------------------------------------------------------------------

func ExampleOptions() {
	//nolint:exhaustruct // allow missing fields
	options := totp.Options{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
	}

	options.SetDefault()

	// Issuer is the name of the service who issued the secret.
	fmt.Println("Issuer:", options.Issuer)
	// Name of the owner of the secret key.
	fmt.Println("AccountName:", options.AccountName)
	// Hash algorithm to generate the passcode as HMAC.
	fmt.Println("Algorithm:", options.Algorithm)
	// Length of the passcode.
	fmt.Println("Digits:", options.Digits)
	// Valid seconds of passcode issued.
	fmt.Println("Period:", options.Period)
	// Size of the secret key in bytes.
	fmt.Println("Secret Size:", options.SecretSize)
	// Skew is an acceptable range of time before and after. Value of 1 allows
	// up to Period of either side of the specified time.
	fmt.Println("Skew:", options.Skew)

	// Output:
	// Issuer: Example.com
	// AccountName: alice@example.com
	// Algorithm: SHA512
	// Digits: 6
	// Period: 30
	// Secret Size: 20
	// Skew: 0
}

// ----------------------------------------------------------------------------
//  Type: Secret
// ----------------------------------------------------------------------------

func ExampleSecret() {
	// The below two lines are the same but with different base-encodings.
	//nolint:gosec // potentially hardcoded credentials for testing
	base32Secret := "MZXW6IDCMFZCAYTVPJ5A"
	//nolint:gosec // potentially hardcoded credentials for testing
	base62Secret := "FegjEGvm7g03GQye"

	// Instantiate a new Secret object from a base32 encoded string.
	secret32, err := totp.NewSecretBase32(base32Secret)
	if err != nil {
		log.Fatal(err)
	}

	// Instantiate a new Secret object from a base62 encoded string.
	secret62, err := totp.NewSecretBase62(base62Secret)
	if err != nil {
		log.Fatal(err)
	}

	// Once instantiated, you can use the Secret object to get the secret in
	// different base-encodings.
	fmt.Println("Get as base62 encoded string:", secret32.Base62())
	fmt.Println("Get as base32 encoded string:", secret62.Base32())

	// String() method is equivalent to Base32()
	if secret62.String() == secret62.Base32() {
		fmt.Println("String() is equivalent to Base32()")
	}

	if secret32.String() == secret62.String() {
		fmt.Println("Two secrets are the same.")
	}

	// Output:
	// Get as base62 encoded string: FegjEGvm7g03GQye
	// Get as base32 encoded string: MZXW6IDCMFZCAYTVPJ5A
	// String() is equivalent to Base32()
	// Two secrets are the same.
}

// ----------------------------------------------------------------------------
//  Type: URI
// ----------------------------------------------------------------------------

func ExampleURI() {
	origin := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	uri := totp.URI(origin)

	// Check if the URI is correctly formatted with the required fields.
	if err := uri.Check(); err != nil {
		log.Fatal(err)
	}

	if uri.String() == origin {
		fmt.Println("Raw URI and String is equal: OK")
	}

	fmt.Println("Scheme:", uri.Scheme())
	fmt.Println("Host:", uri.Host())
	fmt.Println("Issuer:", uri.Issuer())
	fmt.Println("Account Name:", uri.AccountName())
	fmt.Println("Algorithm:", uri.Algorithm())
	fmt.Println("Secret:", uri.Secret().String())
	fmt.Println("Period:", uri.Period())
	fmt.Println("Digits:", uri.Digits())

	// Output:
	// Raw URI and String is equal: OK
	// Scheme: otpauth
	// Host: totp
	// Issuer: Example.com
	// Account Name: alice@example.com
	// Algorithm: SHA1
	// Secret: QF7N673VMVHYWATKICRUA7V5MUGFG3Z3
	// Period: 60
	// Digits: 12
}

func ExampleURI_IssuerFromPath() {
	origin := "otpauth://totp/Example.com:alice@example.com?issuer=Wrong.com"

	uri := totp.URI(origin)

	fmt.Println(uri.IssuerFromPath())

	// Output: Example.com
}
