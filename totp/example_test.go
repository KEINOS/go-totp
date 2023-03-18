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
	if key.Validate(passcode) {
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
	if key.Validate(passcode) {
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

	// Output:
	// Digits: 8
	// Digits ID: 8
	// Digit 8 OK
	// Digit 6 OK
}

// ----------------------------------------------------------------------------
//  Function: GenKeyFromPEM
// ----------------------------------------------------------------------------

func ExampleGenKeyFromPEM() {
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

	// Output:
	// AccountName: alice@example.com
	// Algorithm: SHA1
	// Digits: 8
	// Issuer: Example.com
	// Period: 30
	// Secret Size: 64
	// Skew: 0
	// Secret: QF7N673VMVHYWATKICRUA7V5MUGFG3Z3
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

//nolint:funlen // length is 62 lines long but leave it as is due to embedded example
func ExampleKey_QRCode() {
	origin := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=6&issuer=Example.com&period=30&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	// Create a new Key object from a URI
	key, err := totp.GenerateKeyURI(origin)
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

	actual := fmt.Sprintf("%x", pngImage)
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

	// Output: OK
}

func ExampleKey_PEM() {
	origin := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=6&issuer=Example.com&period=30&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	key, err := totp.GenerateKeyURI(origin)
	if err != nil {
		log.Fatal(err)
	}

	keyPEM, err := key.PEM()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(keyPEM)

	// Output:
	// -----BEGIN TOTP SECRET KEY-----
	// Account Name: alice@example.com
	// Algorithm: SHA1
	// Digits: 6
	// Issuer: Example.com
	// Period: 30
	// Secret Size: 20
	// Skew: 0
	//
	// gX7ff3VlT4sCakCjQH69ZQxTbzs=
	// -----END TOTP SECRET KEY-----
}

func ExampleKey_URI() {
	origin := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	key, err := totp.GenerateKeyURI(origin)
	if err != nil {
		log.Fatal(err)
	}

	expect := origin
	actual := key.URI() // regenerate URI

	if expect == actual {
		fmt.Println("URI returned as expected")
	}

	// Output: URI returned as expected
}

// ----------------------------------------------------------------------------
//  Func: NewOptions()
// ----------------------------------------------------------------------------

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

	// Output:
	// Type: *totp.Options
	// Issuer: Example.com
	// Account Name: alice@example.com
	// Error msg: issuer and accountName are required
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

	// Output:
	// Issuer: Example.com
	// AccountName: alice@example.com
	// Algorithm: SHA1
	// Digits: 6
	// Period: 30
	// Secret Size: 128
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
//  Function: StrToUint
// ----------------------------------------------------------------------------

func ExampleStrToUint() {
	str1 := "1234567890"
	uint1 := totp.StrToUint(str1)

	fmt.Printf("uint1: %v, type: %T\n", uint1, uint1)

	// Note that number that overflows the uint will return 0.
	str2 := fmt.Sprintf("%d", uint64(0xFFFFFFFF+1))
	uint2 := totp.StrToUint(str2)

	fmt.Printf("uint2: %v, type: %T\n", uint2, uint2)

	// Output:
	// uint1: 1234567890, type: uint
	// uint2: 0, type: uint
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

// ----------------------------------------------------------------------------
//  Func: Validate()
// ----------------------------------------------------------------------------

// Validate function is a short hand of totp.Key.Validate() functionality.
func ExampleValidate() {
	// Create a new Key object via URI to obtain the current passcode.
	uri := "otpauth://totp/Example.com:alice@example.com?algorithm=SHA1&" +
		"digits=12&issuer=Example.com&period=60&secret=QF7N673VMVHYWATKICRUA7V5MUGFG3Z3"

	key, err := totp.GenerateKeyURI(uri)
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

	// Output:
	// Passcode is valid. Checked via Key.Validate() method.
	// Passcode is valid. Checked via Validate() function.
}
