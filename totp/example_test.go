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
		// Algorithm choices are: MD5, SHA1, SHA256 and SHA512.
		totp.WithAlgorithm(totp.Algorithm("SHA256")),
		totp.WithPeriod(15),
		totp.WithSecretSize(256),
		totp.WithSkew(5),
		totp.WithDigits(totp.DigitsEight),
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
		fmt.Println("Digit 8", "OK")
	}

	// DigitsSix is equivalent to NewDigits(6)
	if totp.DigitsSix == totp.NewDigitsInt(6) {
		fmt.Println("Digit 6", "OK")
	}
	//
	// Output:
	// Digits: 8
	// Digits ID: 8
	// Digit 8 OK
	// Digit 6 OK
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
	expect := `89504e470d0a1a0a0000000d4948445200000064000000641000000000051` +
		`916cb0000040549444154789ce45ced6edb400c9387bcff2b67180a2f324d5272ff` +
		`95d59f35f7691f4f12a9047bbddf1561afaae3d0dde76bf631bdeddfdffd5f370fd` +
		`7c5f99b7df473fef1eff973ecf5f50fbb60ec74b01dfbce93eba7cce6633fae778e` +
		`617dfc39d310a90101e503bdbff7f55357779ba1727e763ec69f231191c9f094ce1` +
		`3c5c88363b17f4217db7709e23722c20c917077daa1721aa2be4fd789886cdebe9f` +
		`6e3796a927b4703f8c722ad7f0e74c43c4f198d3d489bb2c5dc28fa6f90a19fd9c4` +
		`9883c21f2d33d7ec68fb83994b4c52072bcdf8e1339edd1e76c4f7d42df4536bf5e` +
		`1a2235a8b6291f4c116c52932c32b13d35a28988d4a033f054a6d355e3e5a318e49` +
		`53f7eda9210f9ffa7f095d3143762f3a7317d4d75f2ac4d71b83c443668a87c33f1` +
		`afefa08aa67ceef339061150882ebef77665937e983489da57a1f1b12444b675277` +
		`7f771ceac1f7ccd6bc316aef5b32444746cf6a75ea6eac1906111ab4424ab07dc2f` +
		`2f6a3da9064eda5ef988d335389fadc9d6ba5a0c22c7f5fd9c9ea8413b383e44b71` +
		`e1057be837d79510b4dc56f15a9b67fe33ab8966b57d59bcffa31881085e878ce94` +
		`6f9efa85426ce387578b41c47c3fc232b8d21e7d8eb29e5f7a5b01b25b34aee8262` +
		`1a2388dd3112ab239a5c8d639cd2947e74b15f93dfbe6edcb54fe948a448ec4d6c1` +
		`f570bee263773f4942a408b364a7dfc74cd590d3b61a67529fb8ce7dbf2444d4292` +
		`8fea3fa3677ba067ee5f290afac2421b2b9df657247895f3738fec5c6d7c0a7fc33` +
		`2621c24cc575e507cecfd867c59291b7b95ac115bd34442625876dea2ebb0c8fa7e` +
		`b7899aa9c689f4a4264d20865eeee5431615ac5b16336cead9b19b55cd564527c4e` +
		`6fa87bddc72aff62151b857a586637954616955c1564f22d77baca7fdc3e95f93df` +
		`be02365f4b33aedd354b545b5b1bdd83adc921029f1d6ea2ebbaa8932a5f19d8264` +
		`63b5928d4184fc824e2941759fb7999d459f890de33e257d2c0691d7acbd550c67a` +
		`69800e366ee84fbbc69cf2f4b42a408ffaf21533b1dcea2df661eeea9d6e53e1983` +
		`c8717f371769b0ed0903c6cf133a684abf87b15f52fb75bc0bc73afdcdc697d1e3b` +
		`8a68aa01c993444ca5416ddbd76f7d621d7f798b4067e663e1c94d9e157a6b560a4` +
		`45eeaa53747d5d954fb62c5a5b1222b31edee9f05a565ea63536ebe0b83c1fb1430` +
		`ca3ddf84e5fc75544702fa791ea7653621059fc9f0f4f3484e24f8a2594f9b6d865` +
		`f5fbb82444eac1f77c5d13e058cf4e791f8e719ccd7b731a22356873773fd538869` +
		`ccb190e15c5bb2a568f4ca62257b72d3b9ea2e471785fc1bd33a3d664131a38ae8c` +
		`26a9bafb113b75c584d197c27ca4d57e6f5ddfc80d6abc9a37712dd6c77d330d116` +
		`51839d4bd773ae3b29dc8d893f6708ab2b2aaf10b3df233ec6f000000ffffa0404e` +
		`fb1e0ab59a0000000049454e44ae426082`

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

	expect := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"
	actual := key.String()

	if expect == actual {
		fmt.Println("URI returned as expected")
	}
	//
	// Output: URI returned as expected
}

func ExampleKey_URI() {
	origin := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	key, err := totp.GenKeyFromURI(origin)
	if err != nil {
		log.Fatal(err)
	}

	expect := origin
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

//nolint:exhaustruct // allow missing fields
func ExampleOptions() {
	options := totp.Options{
		Issuer:      "Example.com",
		AccountName: "alice@example.com",
	}

	options.SetDefault()

	/* List all option and their default values. */

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
	//
	// Output:
	// Issuer: Example.com
	// AccountName: alice@example.com
	// Algorithm: SHA1
	// Digits: 6
	// Period: 30
	// Secret Size: 128
	// Skew: 1
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
