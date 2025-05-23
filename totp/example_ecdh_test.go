//nolint:goconst // allow occurrences for readability
package totp_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/KEINOS/go-totp/totp"
)

// This example demonstrates how to generate a new TOTP secret key from a shared
// secret of ECDH (Elliptic Curve Diffie-Hellman) key exchange.
//
// Meaning that two parties can generate a common TOTP passcode by exchanging
// their ECDH public keys.
//
// The aim of this functionality is to allow the user to generate a common but
// ephemeral secret value (the generated TOTP passcode) for additional security.
// Such as time-based salt for hashing, etc.
//
// In this example, we pretend that Alice and Bob want to generate a common TOTP
// passcode for their communication. And they have exchanged their ECDH public
// keys securely with no-man-in-the-middle attack.
//
// Let's see how Alice generates a common TOTP passcode between her and Bob!
func Example_ecdh() {
	// ------------------------------------------------------------------------
	//  Pre-agreement between Alice and Bob.
	// ------------------------------------------------------------------------
	//  Both parties must use the same protocol (agreed options) so that the
	//  same shared secret is created and use it to generate a same TOTP
	//  passcode within the same time frame.
	//
	// The curve type.
	commonCurve := ecdh.X25519()
	// A consistent and common context between the two parties. It will be used
	// as a salt-like value for the TOTP secret key derivation.
	commonCtx := "example.com alice@example.com bob@example.com TOTP secret v1"
	// Common options for the TOTP passcode generation.
	commonOpts := totp.Options{
		AccountName: "",                       // Name of the user. Empty due to be overridden
		Issuer:      "",                       // Name of the service. Empty due to be overridden
		Algorithm:   totp.Algorithm("SHA512"), // Algorithm for passcode generation
		Digits:      totp.DigitsEight,         // Number of digits for the passcode
		Period:      60 * 30,                  // Interval of the passcode validity
		SecretSize:  32,                       // Size of the TOTP secret key in bytes
		Skew:        1,                        // Number of periods as tolerance (+/-)
	}

	// ------------------------------------------------------------------------
	//  Key exchange between Alice and Bob.
	// ------------------------------------------------------------------------
	//  We pretend that Alice and Bob have exchanged their ECDH public keys
	//  securely. In a real-world scenario, you must not expose your private
	//  key to the public by any means.
	alicePriv, alicePub := testGetECDHKeysForAlice(commonCurve)
	bobPriv, bobPub := testGetECDHKeysForBob(commonCurve)

	// ------------------------------------------------------------------------
	//  Generate a new TOTP key for Alice
	// ------------------------------------------------------------------------
	Issuer := "Example.com"            // name of the service
	AccountName := "alice@example.com" // name of the user

	key, err := totp.GenerateKey(Issuer, AccountName,
		// Use the ECDH shared secret between Alice and Bob as the base of the
		// TOTP secret key. A common and consistent context is required.
		//
		// The size of the shared ECDH secret is 32 bytes. The secret TOTP key
		// is therefore derived from this shared secret using the key derivation
		// function (KDF) set in the options to stretch up to the options.SecretSize.
		// The default KDF is BLAKE3.
		totp.WithECDH(alicePriv, bobPub, commonCtx),
		// Other options can be set as well. But they must be the same between
		// the two parties.
		totp.WithAlgorithm(commonOpts.Algorithm),
		totp.WithDigits(commonOpts.Digits),
		totp.WithPeriod(commonOpts.Period),
		totp.WithSecretSize(commonOpts.SecretSize),
		totp.WithSkew(commonOpts.Skew),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Alice generates 8 digits of TOTP passcode
	passcode, err := key.PassCode()
	if err != nil {
		log.Fatal(err)
	}

	// Bob validates the passcode
	result := letBobValidate(passcode, bobPriv, alicePub, commonOpts)
	fmt.Println(result)
	//
	// Output: * Validation result: Passcode is valid
}

func ExampleWithECDHKDF() {
	// ------------------------------------------------------------------------
	//  Pre-agreement between Alice and Bob.
	// ------------------------------------------------------------------------
	//  See the Example_ecdh() example for the details.
	commonCurve := ecdh.X25519()
	commonCtx := "example.com alice@example.com bob@example.com TOTP secret v1"

	// ------------------------------------------------------------------------
	//  Key exchange between Alice and Bob.
	// ------------------------------------------------------------------------
	alicePriv, alicePub := testGetECDHKeysForAlice(commonCurve)
	bobPriv, bobPub := testGetECDHKeysForBob(commonCurve)

	// ------------------------------------------------------------------------
	//  Generate a new TOTP key for Alice
	// ------------------------------------------------------------------------
	Issuer := "Example.com"            // name of the service
	AccountName := "alice@example.com" // name of the user

	key, err := totp.GenerateKey(Issuer, AccountName,
		totp.WithECDH(alicePriv, bobPub, commonCtx),
		// You can assign a custom function to derive the TOTP secret key from
		// the ECDH shared secret. The default is BLAKE3. Any function that
		// implements the totp.KDF interface can be used.
		totp.WithECDHKDF(totp.OptionKDFDefault),
	)
	if err != nil {
		log.Fatal(err)
	}

	commonOpts := key.Options // Bob must use the same options as Alice

	// Alice generates 8 digits of TOTP passcode
	passcode, err := key.PassCode()
	if err != nil {
		log.Fatal(err)
	}

	// Bob validates the passcode
	result := letBobValidate(passcode, bobPriv, alicePub, commonOpts)
	fmt.Println(result)
	//
	// Output: * Validation result: Passcode is valid
}

func letBobValidate(
	alicePasscode string,
	bobPriv *ecdh.PrivateKey,
	alicePub *ecdh.PublicKey,
	commonOpts totp.Options,
) string {
	// Pre-agreement between Alice and Bob.
	commonCtx := "example.com alice@example.com bob@example.com TOTP secret v1"

	// ------------------------------------------------------------------------
	//  Generate a new TOTP key for Bob
	// ------------------------------------------------------------------------
	Issuer := "Example.com"
	AccountName := "bob@example.com"

	key, err := totp.GenerateKey(Issuer, AccountName,
		totp.WithECDH(bobPriv, alicePub, commonCtx),
		totp.WithPeriod(commonOpts.Period),
		totp.WithAlgorithm(commonOpts.Algorithm),
		totp.WithSecretSize(commonOpts.SecretSize),
		totp.WithSkew(commonOpts.Skew),
		totp.WithDigits(commonOpts.Digits),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Bob validates the passcode
	if key.Validate(alicePasscode) {
		return "* Validation result: Passcode is valid"
	}

	return "* Validation result: Passcode is invalid"
}

// This is a dummy function to return Alice's ECDH private key.
// In a real-world scenario, you would generate this key securely.
//
// paramCommon is the curve type agreed between Alice and Bob.
func testGetECDHKeysForAlice(paramCommon ecdh.Curve) (*ecdh.PrivateKey, *ecdh.PublicKey) {
	alicePriv, err := paramCommon.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err, "failed to generate Alice's ECDH private key for example")
	}

	return alicePriv, alicePriv.PublicKey()
}

// This is a dummy function to return Bob's ECDH public key.
// In a real-world scenario, you would obtain this key securely.
//
// paramCommon is the curve type agreed between Alice and Bob.
func testGetECDHKeysForBob(paramCommon ecdh.Curve) (*ecdh.PrivateKey, *ecdh.PublicKey) {
	bobPriv, err := paramCommon.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err, "failed to generate Alice's ECDH private key for example")
	}

	return bobPriv, bobPriv.PublicKey()
}
