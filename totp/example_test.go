// allow potentially hardcoded credentials for testing and occurrences for readability
//
//nolint:gosec,goconst
package totp_test

import (
	"encoding/hex"
	"fmt"
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
	origin := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=6&issuer=Example.com&period=30&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

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

	actual := hex.EncodeToString(pngImage)
	//nolint:lll // long line is intentional
	expect := `89504e470d0a1a0a0000000d4948445200000064000000641000000000051` +
		`916cb0000041c49444154789ce45cd172e4200c3337fbffbf9c9bce4eba449164a7` + `f7549d5fba2160580496053b7d1d4745d8ab6a2dfdfafc9a7b9dbdecebf3fed7b54` + `3bf5d7dd68f1ee71ffdf277d9ebfd872d303603fbcc9c6db0ecebf3398b7bbbdd2f` + `be67fda9fef938d31029b13eb11c679ead5d8690f285a8611943858f331111672a0` + `a61e4daeb33f4d08fdb2bfb1eeced7f438445a5dd1c6fe0ec2b1499cde93a1111f7` + `ed11091561dc8cabb5cfea2baed1e34c43c4e531bb31dee8d67a879caacf229b1e6` + `712224f137936bbfb733559829a6d1c47f77cb524445cbe7fb2315ba76e1d777cc3` + `187eb72ec7427f598894506138c3bb29be506bde451e9529ab2c98fb894164bdbf1` + `fb2ae62f00eb127c83a7e61c6d4e9e73906914db3637ee3347977aa81ed989fd350` + `abb0f7d59e21a421729acb5e156f9ce6d4639557888af15db67d1d471222fb1a756` + `b5acd9e5afb2a53467fae9dca00eebe931039add3192a4b75a725d56898096794e0` + `a26ba48d41645de757c579349763e173a7e1779f7298a2afcca8b51b8be51d3abbb` + `968a3b8a98a6b17e7fbce298988fc8433dc67b6e6153333d45574e4be63101151eb` + `34a71f587dd716cbbb68f84ce7a421c2f6849a0da7addbee1a4dae78c9b57d5b0c2` + `22f9ebf38e66619b25bcb7b5dad277cd6dbf515b447c469bc62e022eccfea57c327` + `4bdcee76592efaff580c22eb38d4fa479bc47ff5ac7c7d0f639055b8b1e4ee914e3` + `74cf329a56b1c37615f6a8f2e7abf9884885afb4ef5b1b2a91fe7ff49ffb9a72813` + `ed3055892c02765abce0660cfd74e3795b122235b8c353acaad041e6577eca9c3ab` + `268a9fac9e211b6a65d8462b3c3b477998c9631b7db5f8e5f56d6fdc8d231e5895a` + `ec3282dd545ee6b40f433057b3eb9309cfae2c92395fb7ae1bada2ce09f81a4a42a` + `48436de9f6fcd06f7e98e7ba67aa41b4f268f9cf6244752f5260839f5a722533796` + `ac3dd2451515e3591d1771ba28560df7a8f1bd2d0991cba360e749cec4da6359170` + `dd538d858ae7dc720427ed3a858bd865ca018ff38663c81653cdbbdf69bc7234ab9` + `a1b948540231979f617f4fa2dfd56210d9a2d624eb54ccad4cadf5a71aa6eb2f6f8f` + `94c8b5e67a80cf6cb777941f8594de973188c0adee77f1c35bd6dd9cdebe75ff8f77` + `2d47ec1d629173d8bddc6908b7a67faaf7b12d7bbe962721d2ebe15e43b08c7499df` + `6075992d96e3e7bbbf24443a5ee86645a151e6eeef093f313ff7681a83089c34a239` + `65d765cc2eda29c5c9fcb93df8a91783c8e07f3eb0f5ecd67ac707580723a24311fd` + `7edea72152c3138e633bf9eb189ef1883b6141ee717c84ed321171c6325a2c533abd` + `065c84a72c35886c2bfa17749dddd7e4a71cff2aee515ce47886ed557c17b64706a7` + `f135e006952fb9768ab1b11dd7e8e8270691c1ff7c503ac34515b69fd0570d4eddd9` + `331f6f0c22e6970fbfcbfe060000ffff11a9592e12644af00000000049454e44ae42` +
		`6082`

	// Assert equal image
	if expect == actual {
		fmt.Println("OK")
	}
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
	//
	//nolint:exhaustruct // missing fields allowed due to be an example
	options := totp.Options{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
	}

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
