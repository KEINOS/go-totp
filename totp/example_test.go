// allow potentially hardcoded credentials for testing and occurrences for readability
//
//nolint:gosec,goconst
package totp_test

import (
	"bytes"
	"fmt"
	"image/png"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/KEINOS/go-totp/totp"
)

// ============================================================================
//  Package Examples
// ============================================================================

// This example demonstrates how to generate a new secret key with default
// options and validate the passcode.
//
// The generated key should be compatible with most TOTP authenticator apps.
func Example() {
	Issuer := "Example.com"            // name of the service
	AccountName := "alice@example.com" // name of the user

	// Generate a new secret key with default options.
	// Compatible with most TOTP authenticator apps.
	key, err := totp.GenerateKey(Issuer, AccountName)
	if err != nil {
		log.Fatal(err)
	}

	// Print the default option values.
	fmt.Println("- Algorithm:", key.Options.Algorithm)
	fmt.Println("- Period:", key.Options.Period)
	fmt.Println("- Secret Size:", key.Options.SecretSize)
	fmt.Println("- Skew (time tolerance):", key.Options.Skew)
	fmt.Println("- Digits:", key.Options.Digits)

	// Generate 6 digits passcode (valid for 30 seconds)
	passcode, err := key.PassCode()
	if err != nil {
		log.Fatal(err)
	}

	// Validate the passcode
	if key.Validate(passcode) {
		fmt.Println("* Validation result: Passcode is valid")
	}
	//
	// Output:
	// - Algorithm: SHA1
	// - Period: 30
	// - Secret Size: 128
	// - Skew (time tolerance): 1
	// - Digits: 6
	// * Validation result: Passcode is valid
}

// This example demonstrates how to generate a new secret key with `GenerateKeyCustom`.
// But it is recommended to use the `GenerateKey` function with `With*` options.
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
	if key.Validate(passcode) {
		fmt.Println("Passcode is valid")
	}
	//
	// Output: Passcode is valid
}

// This example demonstrates how to generate a new secret key with custom options
// and validate the passcode.
//
// Since most TOTP authenticator apps are based on SHA1 hashing algorithm to
// generate the passcode, this example is useful when you need to generate the
// passcode with a stronger hash algorithm such as SHA256 and SHA512.
func Example_custom() {
	// Generate a new secret key with custom options
	Issuer := "Example.com"
	AccountName := "alice@example.com"

	key, err := totp.GenerateKey(Issuer, AccountName,
		totp.WithAlgorithm(totp.Algorithm("SHA256")), // Algorithm for passcode generation (MD5, SHA1, SHA256 and SHA512)
		totp.WithPeriod(15),                          // Interval of the passcode validity
		totp.WithSecretSize(256),                     // Size of the TOTP secret key in bytes
		totp.WithSkew(5),                             // Number of periods as tolerance (+/-)
		totp.WithDigits(totp.DigitsEight),            // Number of digits for the passcode
	)
	if err != nil {
		log.Fatal(err)
	}

	// Generate 8 digits passcode (valid for 15 ± 5 seconds)
	passcode, err := key.PassCode()
	if err != nil {
		log.Fatal(err)
	}

	// Validate the passcode
	if key.Validate(passcode) {
		fmt.Println("Passcode is valid")
	}
	//
	// Output: Passcode is valid
}

// As of v0.3.0, the "totp.Key.URI()" method returns the URI string with the
// "secret" query parameter first by default.
//
// This is due to avoid a niche reading error bug of Google Authenticator (#55).
// QR Code generated with other libraries that uses an old encoding method, Google
// Authenticator fails to read if the URI in the QR Code ends with a "secret" query
// parameter.
//
//nolint:lll // exceeding the maximum line length in the output is intentional
func Example_secret_param_first() {
	// note the order of the query parameters
	origin := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"period=60&issuer=Example.com&digits=12&" +
		"secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	key, err := totp.GenKeyFromURI(origin)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(key.URI())
	//
	// Output:
	// otpauth://totp/Example.com:alice@example.com?secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3&algorithm=SHA1&digits=12&issuer=Example.com&period=60
}

// ============================================================================
//  Type: Algorithm
// ============================================================================

func ExampleAlgorithm() {
	// Create a new Algorithm object from a string for passcode generation.
	// Choices are:
	//   MD5, SHA1, SHA256 and SHA512.
	algo, err := totp.NewAlgorithmStr("SHA512")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Algorithm:", algo.String())
	fmt.Println("Algorithm ID:", algo.ID())
	fmt.Printf("Type: %T\n", algo.OTPAlgorithm())
	//
	// Output:
	// Algorithm: SHA512
	// Algorithm ID: 2
	// Type: otp.Algorithm
}

func ExampleAlgorithm_IsSupported() {
	// Set unsupported algorithm for passcode generation
	algo := totp.Algorithm("BLAKE3")

	// Check if the algorithm is supported
	if algo.IsSupported() {
		fmt.Println("Algorithm is supported")
	} else {
		fmt.Println("Algorithm is not supported")
	}
	//
	// Output: Algorithm is not supported
}

// ============================================================================
//  Type: Digits
// ============================================================================

func ExampleDigits() {
	// Create a new Digits object from a number. Choices are:
	//   6 and 8.
	digits := totp.NewDigitsInt(8)

	fmt.Println("Digits:", digits)
	fmt.Println("Digits ID:", digits.OTPDigits())

	// DigitsEight is equivalent to NewDigits(8)
	if totp.DigitsEight == totp.NewDigitsInt(8) {
		fmt.Println("Digit 8:", "OK")
	}

	// DigitsSix is equivalent to NewDigits(6)
	if totp.DigitsSix == totp.NewDigitsInt(6) {
		fmt.Println("Digit 6:", "OK")
	}

	// Negative input will enforce the default value of 6 digits.
	if totp.DigitsSix == totp.NewDigitsInt(-1) {
		fmt.Println("Negative input is enforced to 6 digits:", "OK")
	}
	//
	// Output:
	// Digits: 8
	// Digits ID: 8
	// Digit 8: OK
	// Digit 6: OK
	// Negative input is enforced to 6 digits: OK
}

// ============================================================================
//  Func: GenKeyFromPEM (fka GenerateKeyPEM)
// ============================================================================

func ExampleGenKeyFromPEM() {
	pemData := `
-----BEGIN TOTP SECRET KEY-----
Account Name: alice@example.com
Algorithm: SHA1
Digits: 8
Issuer: Example.com
Period: 30
Secret Size: 64
Skew: 1

gX7ff3VlT4sCakCjQH69ZQxTbzs=
-----END TOTP SECRET KEY-----`

	key, err := totp.GenKeyFromPEM(pemData)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("AccountName:", key.Options.AccountName)
	fmt.Println("Algorithm:", key.Options.Algorithm)
	fmt.Println("Digits:", key.Options.Digits)
	fmt.Println("Issuer:", key.Options.Issuer)
	fmt.Println("Period:", key.Options.Period)
	fmt.Println("Secret Size:", key.Options.SecretSize)
	fmt.Println("Skew:", key.Options.Skew)
	fmt.Println("Secret:", key.Secret.Base32())
	//
	// Output:
	// AccountName: alice@example.com
	// Algorithm: SHA1
	// Digits: 8
	// Issuer: Example.com
	// Period: 30
	// Secret Size: 64
	// Skew: 1
	// Secret: QF7N673VMVHYWATKICRUA7V5MUGFG3Z3
}

// ============================================================================
//  Func: GeneKeyFromURI (fka GenerateKeyURI)
// ============================================================================

func ExampleGenKeyFromURI() {
	origin := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	key, err := totp.GenKeyFromURI(origin)
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
	//
	// Output:
	// Issuer: Example.com
	// AccountName: alice@example.com
	// Algorithm: SHA1
	// Digits: 12
	// Period: 60
	// Secret Size: 20
	// Secret: QF7N673VMVHYWATKICRUA7V5MUGFG3Z3
}

// ============================================================================
//  Type: Key
// ============================================================================

func ExampleKey() {
	// Generate a new secret key with default options.
	Issuer := "Example.com"
	AccountName := "alice@example.com"

	key, err := totp.GenerateKey(Issuer, AccountName)
	if err != nil {
		log.Fatal(err)
	}

	// Generate 6 digits passcode (valid for 30 seconds)
	// For generating a passcode for a custom time, use PassCodeCustom() method.
	passCode, err := key.PassCode()
	if err != nil {
		log.Fatal(err)
	}

	// Validate the passcode
	if key.Validate(passCode) {
		fmt.Println("Given passcode is valid")
	}
	//
	// Output:
	// Given passcode is valid
}

// In this example, we will re-generate/recover a new Key object from a backed-up
// secret key value.
//
// The point to recover the Key object is simply to overwrite the secret key value
// with the backed-up value.
//
// If you simply want to validate a passcode with a backed-up secret key value,
// use the totp.Validate() function instead.
//
//nolint:gosec // potentially hardcoded credentials for testing
func ExampleKey_regenerate1() {
	// The backed-up secret key value (in case of Base32 encoded)
	oldSecret := "QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	// Step1: Generate a brand new Key object
	Issuer := "Example.com"
	AccountName := "alice@example.com"

	key, err := totp.GenerateKey(Issuer, AccountName)
	if err != nil {
		log.Fatal(err)
	}

	// Step2: Cast the backed-up secret key value to a Secret object
	newSecret, err := totp.NewSecretBase32(oldSecret)
	if err != nil {
		log.Fatal(err)
	}

	// Step3: Ensure the secret key size is the same as the new key object
	key.Options.SecretSize = uint(len(newSecret.Bytes()))

	// Step4: Overwrite the secret key value with the backed-up value
	key.Secret = newSecret

	// Step5: Backup the TOTP key object in PEM format this time
	keyPEM, err := key.PEM()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(keyPEM) // Save this data
	//
	// Output:
	// -----BEGIN TOTP SECRET KEY-----
	// Account Name: alice@example.com
	// Algorithm: SHA1
	// Digits: 6
	// Issuer: Example.com
	// Period: 30
	// Secret Size: 20
	// Skew: 1
	//
	// gX7ff3VlT4sCakCjQH69ZQxTbzs=
	// -----END TOTP SECRET KEY-----
}

// In this example, we will re-generate/recover a new Key object from a backed-up
// secret key value.
//
// This does the same as the previous example but with a different approach. Choose
// the one that suits your needs.
//
//nolint:gosec // potentially hardcoded credentials for testing
func ExampleKey_regenerate2() {
	// Step1: Generate a totp.Secret object from a backed-up secret key value
	secret, err := totp.NewSecretBase32("QF7N673VMVHYWATKICRUA7V5MUGFG3Z3")
	if err != nil {
		log.Fatal(err)
	}

	// Step2: Generate a new totp.Options object with default values but with the
	// secret key size set to the same as the backed-up secret key value.
	options, err := totp.NewOptions("Example.com", "alice@example.com")
	if err != nil {
		log.Fatal(err)
	}

	options.SecretSize = uint(len(secret.Bytes()))

	// Step3: Generate a new totp.Key object.
	key := totp.Key{
		Secret:  secret,
		Options: *options,
	}

	// Step4: Backup the TOTP key object in PEM format this time
	keyPEM, err := key.PEM()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(keyPEM) // Save this data
	//
	// Output:
	// -----BEGIN TOTP SECRET KEY-----
	// Account Name: alice@example.com
	// Algorithm: SHA1
	// Digits: 6
	// Issuer: Example.com
	// Period: 30
	// Secret Size: 20
	// Skew: 1
	//
	// gX7ff3VlT4sCakCjQH69ZQxTbzs=
	// -----END TOTP SECRET KEY-----
}

func ExampleKey_PassCode() {
	// Generate a new secret key
	Issuer := "Example.com"
	AccountName := "alice@example.com"

	key, err := totp.GenerateKey(Issuer, AccountName)
	if err != nil {
		log.Fatal(err)
	}

	// Generate 6 digits passcode (valid for 30 seconds)
	code, err := key.PassCode()
	if err != nil {
		log.Fatal(err)
	}

	// Validate the passcode
	if key.Validate(code) {
		fmt.Println("Passcode is valid with current time")
	}

	// Validate the passcode with a custom time
	validationTime := time.Now().Add(-300 * time.Second)

	if key.ValidateCustom(code, validationTime) {
		fmt.Println("Passcode is valid with custom time")
	} else {
		fmt.Println("Passcode is invalid with custom time")
	}
	//
	// Output:
	// Passcode is valid with current time
	// Passcode is invalid with custom time
}

func ExampleKey_PassCodeCustom() {
	// Generate a new secret key
	Issuer := "Example.com"
	AccountName := "alice@example.com"

	key, err := totp.GenerateKey(Issuer, AccountName)
	if err != nil {
		log.Fatal(err)
	}

	timeNow := time.Now()

	// Generate a passcode for a specific time (300 seconds ago)
	code, err := key.PassCodeCustom(timeNow.Add(-300 * time.Second))
	if err != nil {
		log.Fatal(err)
	}

	// Validating with the current time should fail
	if key.Validate(code) {
		fmt.Println("Passcode is valid with current time")
	} else {
		fmt.Println("Passcode is invalid with current time")
	}

	// To validate a passcode for a specific time, use ValidateCustom()
	// method.
	validationTime := timeNow.Add(-300 * time.Second)

	if key.ValidateCustom(code, validationTime) {
		fmt.Println("Passcode is valid with custom time")
	} else {
		fmt.Println("Passcode is invalid with custom time")
	}
	//
	// Output:
	// Passcode is invalid with current time
	// Passcode is valid with custom time
}

func ExampleKey_PEM() {
	origin := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=6&issuer=Example.com&period=30&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	key, err := totp.GenKeyFromURI(origin)
	if err != nil {
		log.Fatal(err)
	}

	keyPEM, err := key.PEM()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(keyPEM)
	//
	// Output:
	// -----BEGIN TOTP SECRET KEY-----
	// Account Name: alice@example.com
	// Algorithm: SHA1
	// Digits: 6
	// Issuer: Example.com
	// Period: 30
	// Secret Size: 20
	// Skew: 1
	//
	// gX7ff3VlT4sCakCjQH69ZQxTbzs=
	// -----END TOTP SECRET KEY-----
}

func ExampleKey_QRCode() {
	// Appending '&' at the end of the URI prevents the bug of Google
	// Authenticator (iPhone) reading the QR code incorrectly.
	origin := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=6&issuer=Example.com&period=30&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3&"

	// Create a new Key object from a URI
	key, err := totp.GenKeyFromURI(origin)
	if err != nil {
		log.Fatal(err)
	}

	// Create QRCode object
	imgQRCode, err := key.QRCode(totp.FixLevelDefault)
	if err != nil {
		log.Fatal(err)
	}

	// Get PNG image in bytes
	pngImage, err := imgQRCode.PNG(100, 100)
	if err != nil {
		log.Fatal(err)
	}

	// Verify that the generated bytes are valid PNG with the requested size.
	decodedImage, err := png.Decode(bytes.NewReader(pngImage))
	if err != nil {
		log.Fatal(err)
	}

	if decodedImage.Bounds().Dx() != 100 || decodedImage.Bounds().Dy() != 100 {
		log.Fatal("unexpected QR code image size")
	}

	fmt.Println("OK")
	//
	// Output: OK
}

func ExampleKey_String() {
	origin := `
-----BEGIN TOTP SECRET KEY-----
Account Name: alice@example.com
Algorithm: SHA1
Digits: 12
Issuer: Example.com
Period: 60
Secret Size: 20
Skew: 0

gX7ff3VlT4sCakCjQH69ZQxTbzs=
-----END TOTP SECRET KEY-----
`

	key, err := totp.GenKeyFromPEM(origin)
	if err != nil {
		log.Fatal(err)
	}

	expect := "otpauth://totp/Example.com:alice@example.com?" +
		"secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3&" +
		"algorithm=SHA1&digits=12&issuer=Example.com&period=60"
	actual := key.String()

	if expect == actual {
		fmt.Println("URI returned as expected")
	}
	//
	// Output: URI returned as expected
}

func ExampleKey_URI() {
	// Note that the "secret" query parameter (Base32 encoded) is at the end of
	// the URI.
	origin := "otpauth://totp/Example.com:alice@example.com?" +
		"digits=12&algorithm=SHA1&period=60&issuer=Example.com&" +
		"secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	key, err := totp.GenKeyFromURI(origin)
	if err != nil {
		log.Fatal(err)
	}

	// As of v0.3.0, the Key.URI() method returns the URI with the secret as the
	// first query parameter. For details see issue #55.
	expect := "otpauth://totp/Example.com:alice@example.com?" +
		"secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3&" +
		"algorithm=SHA1&digits=12&issuer=Example.com&period=60"

	actual := key.URI() // regenerate URI

	if expect == actual {
		fmt.Println("URI returned as expected")
	}
	//
	// Output: URI returned as expected
}

// ============================================================================
//  Func: NewOptions()
// ============================================================================

func ExampleNewOptions() {
	// Create a new Options object with default values.
	opt1, err := totp.NewOptions("Example.com", "alice@example.com")
	if err != nil {
		log.Fatal(err)
	}

	// For default values, see the example of Options type.
	fmt.Printf("Type: %T\n", opt1)
	fmt.Printf("Issuer: %s\n", opt1.Issuer)
	fmt.Printf("Account Name: %s\n", opt1.AccountName)

	// Issuer and Account Name are required.
	opt2, err := totp.NewOptions("", "")
	// Assert error
	if err != nil {
		fmt.Println("Error msg:", err.Error())
	}
	// Assert nil on error
	if opt2 != nil {
		log.Fatal("NewOptions() should return nil on error")
	}
	//
	// Output:
	// Type: *totp.Options
	// Issuer: Example.com
	// Account Name: alice@example.com
	// Error msg: issuer and accountName are required
}

// ============================================================================
//  Func: NewSecretBytes()
// ============================================================================

func ExampleNewSecretBytes() {
	data := []byte("some secret")

	// Generate a new Secret object from a byte slice.
	secret := totp.NewSecretBytes(data)

	fmt.Printf("Type: %T\n", secret)
	fmt.Printf("Value: %#v\n", secret)
	fmt.Printf("Secret bytes: %#x\n", secret.Bytes())
	fmt.Println("Secret string:", secret.String())
	fmt.Println("Secret Base32:", secret.Base32())
	fmt.Println("Secret Base62:", secret.Base62())
	fmt.Println("Secret Base64:", secret.Base64())
	//
	// Output:
	// Type: totp.Secret
	// Value: totp.Secret{0x73, 0x6f, 0x6d, 0x65, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74}
	// Secret bytes: 0x736f6d6520736563726574
	// Secret string: ONXW2ZJAONSWG4TFOQ
	// Secret Base32: ONXW2ZJAONSWG4TFOQ
	// Secret Base62: bfF9D3ygDyVQZp2
	// Secret Base64: c29tZSBzZWNyZXQ=
}

// ============================================================================
//  Type: Options
// ============================================================================

func ExampleOptions_SetDefault() {
	options, err := totp.NewOptions("Example.com", "alice@example.com")
	if err != nil {
		log.Fatal(err)
	}

	options.SetDefault() // reset all the fields to their default values.

	/* List all exposed options and their values after reset. */
	fmt.Printf("Issuer: \"%v\"\n", options.Issuer)
	fmt.Printf("AccountName: \"%v\"\n", options.AccountName)
	fmt.Printf("Algorithm: \"%v\"\n", options.Algorithm)
	fmt.Printf("Digits: \"%v\"\n", options.Digits)
	fmt.Printf("Period: \"%v\"\n", options.Period)
	fmt.Printf("Secret Size: \"%v\"\n", options.SecretSize)
	fmt.Printf("Skew: \"%v\"\n", options.Skew)
	//
	// Output:
	// Issuer: ""
	// AccountName: ""
	// Algorithm: "SHA1"
	// Digits: "6"
	// Period: "30"
	// Secret Size: "128"
	// Skew: "1"
}

func ExampleOptions() {
	// You may instantiate Options directly but it's recommended to use
	// NewOptions() for convenience.
	options := new(totp.Options)
	options.Issuer = "Example.com"
	options.AccountName = "alice@example.com"

	/* List all exposed options and their values */
	fmt.Printf("Issuer: \"%v\"\n", options.Issuer)
	fmt.Printf("AccountName: \"%v\"\n", options.AccountName)
	fmt.Printf("Algorithm: \"%v\"\n", options.Algorithm)
	fmt.Printf("Digits: \"%v\"\n", options.Digits)
	fmt.Printf("Period: \"%v\"\n", options.Period)
	fmt.Printf("Secret Size: \"%v\"\n", options.SecretSize)
	fmt.Printf("Skew: \"%v\"\n", options.Skew)
	//
	// Output:
	// Issuer: "Example.com"
	// AccountName: "alice@example.com"
	// Algorithm: ""
	// Digits: "0"
	// Period: "0"
	// Secret Size: "0"
	// Skew: "0"
}

// ============================================================================
//  Type: Secret
// ============================================================================

func ExampleSecret() {
	// The below lines are the same but with different base-encodings.
	base32Secret := "MZXW6IDCMFZCAYTVPJ5A"
	base62Secret := "FegjEGvm7g03GQye"
	base64Secret := "Zm9vIGJhciBidXp6"

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

	// Instantiate a new Secret object from a base64 encoded string.
	secret64, err := totp.NewSecretBase64(base64Secret)
	if err != nil {
		log.Fatal(err)
	}

	// Once instantiated, you can use the Secret object to get the secret in
	// different base-encodings.
	fmt.Println("Get as base32 encoded string:", secret64.Base32())
	fmt.Println("Get as base62 encoded string:", secret64.Base62())
	fmt.Println("Get as base64 encoded string:", secret32.Base64())

	// String() method is equivalent to Base32()
	if secret62.String() == secret62.Base32() {
		fmt.Println("String() is equivalent to Base32()")
	}

	// To obtain the raw secret value, use the Bytes() method.
	fmt.Printf("Base32 secret: %x\n", secret32.Bytes())
	fmt.Printf("Base62 secret: %x\n", secret62.Bytes())
	fmt.Printf("Base64 secret: %x\n", secret64.Bytes())
	//
	// Output:
	// Get as base32 encoded string: MZXW6IDCMFZCAYTVPJ5A
	// Get as base62 encoded string: FegjEGvm7g03GQye
	// Get as base64 encoded string: Zm9vIGJhciBidXp6
	// String() is equivalent to Base32()
	// Base32 secret: 666f6f206261722062757a7a
	// Base62 secret: 666f6f206261722062757a7a
	// Base64 secret: 666f6f206261722062757a7a
}

func ExampleSecret_Base64() {
	Issuer := "Example.com"            // name of the service
	AccountName := "alice@example.com" // name of the user

	// Generate a new secret key with default options.
	// Compatible with most TOTP authenticator apps.
	key, err := totp.GenerateKey(Issuer, AccountName)
	if err != nil {
		log.Fatal(err)
	}

	// Base64 encoded secret key is the same encoding used in the PEM data.
	secBase64 := key.Secret.Base64()

	pemData, err := key.PEM()
	if err != nil {
		log.Fatal(err)
	}

	// Chunk the base64 encoded secret key to 64 characters per line.
	// Since the secret in PEM data is usually word-wrapped at 64 characters per
	// line.
	const lenSplit = 64

	var lines []string

	for index, char := range secBase64 {
		if index%lenSplit == 0 {
			lines = append(lines, "")
		}

		lines[len(lines)-1] += string(char)
	}

	// Check if the base64 encoded secret key is found in the PEM data.
	for index, line := range lines {
		if strings.Contains(pemData, line) {
			fmt.Println(index+1, "Base64 encoded secret key is found in PEM data")
		} else {
			fmt.Println(pemData)
			fmt.Println(secBase64)
		}
	}
	//
	// Output:
	// 1 Base64 encoded secret key is found in PEM data
	// 2 Base64 encoded secret key is found in PEM data
	// 3 Base64 encoded secret key is found in PEM data
}

// ============================================================================
//  Func: StrToUint
// ============================================================================

func ExampleStrToUint() {
	str1 := "1234567890"
	uint1 := totp.StrToUint(str1)

	fmt.Printf("uint1: %v, type: %T\n", uint1, uint1)

	// Note that number that overflows the uint will return 0.
	str2 := strconv.FormatUint(uint64(0xFFFFFFFF+1), 10)
	uint2 := totp.StrToUint(str2)

	fmt.Printf("uint2: %v, type: %T\n", uint2, uint2)
	//
	// Output:
	// uint1: 1234567890, type: uint
	// uint2: 0, type: uint
}

// ============================================================================
//  Type: URI
// ============================================================================

func ExampleURI() {
	origin := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	uri := totp.URI(origin)

	// Check if the URI is correctly formatted with the required fields.
	err := uri.Check()
	if err != nil {
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
	//
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
	//
	// Output: Example.com
}

// ============================================================================
//  Func: Validate()
// ============================================================================

// Validate function is a short hand of totp.Key.Validate() functionality.
func ExampleValidate() {
	// Create a new Key object via URI to obtain the current passcode.
	uri := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	key, err := totp.GenKeyFromURI(uri)
	if err != nil {
		log.Fatal(err)
	}

	// Get values needed for the function arguments.
	options := key.Options
	secret := key.Secret.Base32()

	passcode, err := key.PassCode()
	if err != nil {
		log.Fatal(err)
	}

	// Validate the passcode via Key.Validate() method.
	if key.Validate(passcode) {
		fmt.Println("Passcode is valid. Checked via Key.Validate() method.")
	}

	// Validate the passcode via Validate() function.
	if totp.Validate(passcode, secret, options) {
		fmt.Println("Passcode is valid. Checked via Validate() function.")
	}
	//
	// Output:
	// Passcode is valid. Checked via Key.Validate() method.
	// Passcode is valid. Checked via Validate() function.
}
