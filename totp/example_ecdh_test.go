package totp_test

import (
	"crypto/ecdh"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha3"
	"fmt"
	"log"
	"math"

	"github.com/KEINOS/go-totp/totp"
	"github.com/pkg/errors"
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

	// The curve type.
	commonCurve := ecdh.X25519()
	// A consistent and common context between the two parties.
	// It will be used as a salt-like value for the TOTP secret key derivation.
	commonCtx := "It can be any string but consistent between Alice and Bob."

	// ------------------------------------------------------------------------
	//  Generate a new ECDH keys for Alice and Bob
	// ------------------------------------------------------------------------
	//  We pretend that Alice and Bob have exchanged their ECDH public keys
	//  securely. In a real-world scenario, you must not expose your private
	//  key to the public by any means.

	generateECDHKeys := func(commonCurve ecdh.Curve) (*ecdh.PrivateKey, *ecdh.PublicKey) {
		priv, err := commonCurve.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err, "failed to generate ECDH private key")
		}

		return priv, priv.PublicKey()
	}

	ecdhPrivAlice, ecdhPubAlice := generateECDHKeys(commonCurve)
	ecdhPrivBob, ecdhPubBob := generateECDHKeys(commonCurve)

	// ------------------------------------------------------------------------
	//  Alice Side
	// ------------------------------------------------------------------------
	issuerAlice := "Example.com"            // name of the service
	accountNameAlice := "alice@example.com" // name of the user

	totpKeyAlice, err := totp.GenerateKey(issuerAlice, accountNameAlice,
		// Use the ECDH shared secret between Alice and Bob as the base of the
		// TOTP secret key. A common and consistent context is required.
		//
		// The size of the shared ECDH secret is 32 bytes. The secret TOTP key
		// is therefore derived from this shared secret using the key derivation
		// function (KDF) set in the options to stretch up to the options.SecretSize.
		// The default KDF is BLAKE3.
		totp.WithECDH(ecdhPrivAlice, ecdhPubBob, commonCtx),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Alice generates 8 digits of TOTP passcode
	passcodeAlice, err := totpKeyAlice.PassCode()
	if err != nil {
		log.Fatal(err)
	}

	// ------------------------------------------------------------------------
	//  Bob Side
	// ------------------------------------------------------------------------
	issuerBob := "Example.com"
	accountNameBob := "alice@example.com"

	totpKeyBob, err := totp.GenerateKey(issuerBob, accountNameBob,
		totp.WithECDH(ecdhPrivBob, ecdhPubAlice, commonCtx),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Bob generates 8 digits of TOTP passcode
	passcodeBob, err := totpKeyBob.PassCode()
	if err != nil {
		log.Fatal(err)
	}

	// ------------------------------------------------------------------------
	//  Validataion
	// ------------------------------------------------------------------------
	if passcodeAlice == passcodeBob {
		fmt.Println("* Validation result: Passcode matches")
	}
	//
	// Output: * Validation result: Passcode matches
}

// This example demonstrates how to use a custom key derivation function (KDF)
// for the TOTP secret key.
func Example_ecdh_with_custom_KDF() {
	// ------------------------------------------------------------------------
	//  Pre-agreement between Alice and Bob.
	// ------------------------------------------------------------------------
	commonCurve := ecdh.X25519()
	commonCtx := "arbitrary string but consistent between Alice and Bob"

	// Custom key derivation function (KDF) for the TOTP secret key.
	//
	// It uses PBKDF2 from the crypto/pbkdf2 package with SHA3-256 and 4096
	// iterations. The "secret" is the ECDH shared secret. "ctx" is used as
	// the salt to derive the TOTP secret key, and "outLen" is the desired
	// length of the derived TOTP secret key.
	commonKDF := func(secret []byte, ctx []byte, outLen uint) ([]byte, error) {
		const iter = 4096

		// At least 8 bytes is recommended by the RFC.
		if len(ctx) < 8 {
			return nil, errors.New("context too short. PBKDF2 requires at least 8 bytes")
		}

		// Check for potential integer overflow during uint to int conversion
		if outLen == 0 || outLen > math.MaxInt {
			return nil, errors.New("output length is out of valid range for int conversion")
		}

		return pbkdf2.Key(sha3.New256, string(secret), ctx, iter, int(outLen))
	}

	// ------------------------------------------------------------------------
	//  Generate a new ECDH keys for Alice and Bob
	// ------------------------------------------------------------------------
	generateECDHKeys := func(paramCommon ecdh.Curve) (*ecdh.PrivateKey, *ecdh.PublicKey) {
		priv, err := paramCommon.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err, "failed to generate ECDH private key")
		}

		return priv, priv.PublicKey()
	}

	//  We pretend that Alice and Bob have exchanged their ECDH public keys
	ecdhPrivAlice, ecdhPubAlice := generateECDHKeys(commonCurve)
	ecdhPrivBob, ecdhPubBob := generateECDHKeys(commonCurve)

	// ------------------------------------------------------------------------
	//  Alice Side
	// ------------------------------------------------------------------------

	// Generate a new TOTP key for Alice using ECDH key and common context
	totpKeyAlice, err := totp.GenerateKey("Example.com", "alice@example.com",
		totp.WithECDH(ecdhPrivAlice, ecdhPubBob, commonCtx),
		// Assign a custom function to derive the TOTP secret key from the ECDH
		// shared secret. If not set, totp.OptionKDFDefault will be used, which
		// is BLAKE3.
		totp.WithECDHKDF(commonKDF),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Alice generates 8 digits of TOTP passcode
	passcodeAlice, err := totpKeyAlice.PassCode()
	if err != nil {
		log.Fatal(err)
	}

	// ------------------------------------------------------------------------
	//  Bob Side
	// ------------------------------------------------------------------------

	// Generate a new TOTP key for Bob using ECDH key and common context
	totpKeyBob, err := totp.GenerateKey("Example.com", "bob@example.com",
		totp.WithECDH(ecdhPrivBob, ecdhPubAlice, commonCtx),
		totp.WithECDHKDF(commonKDF),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Bob generates 8 digits of TOTP passcode
	passcodeBob, err := totpKeyBob.PassCode()
	if err != nil {
		log.Fatal(err)
	}

	// ------------------------------------------------------------------------
	//  Validataion
	// ------------------------------------------------------------------------
	if passcodeAlice == passcodeBob {
		fmt.Println("* Validation result: Passcode matches")
	}
	//
	// Output: * Validation result: Passcode matches
}
