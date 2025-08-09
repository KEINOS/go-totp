# go-totp

[![go1.24+](https://img.shields.io/badge/Go-1.24+-blue?logo=go)](https://github.com/KEINOS/go-totp/blob/main/.github/workflows/unit-tests.yml#L81 "Supported versions")
[![Go Reference](https://pkg.go.dev/badge/github.com/KEINOS/go-totp.svg)](https://pkg.go.dev/github.com/KEINOS/go-totp/totp "View document")

`go-totp` is a simple Go package to implement [Timebased-One-Time-Password](https://en.wikipedia.org/wiki/Time-based_one-time_password) authentication functionality, a.k.a. `TOTP`, to the Go app.

As an optional feature, this package __supports [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) (Elliptic-Curve Diffie-Hellman) key agreement protocol__, where public keys are exchanged between two parties to obtain a common TOTP passcode.

- [Compatible Authenticator apps](https://github.com/KEINOS/go-totp/wiki/List-of-compatibility) | Wiki @ GitHub

> __Note__: This is a wrapper of the awesome [`github.com/pquerna/otp`](https://github.com/pquerna/otp) package to facilitate the use of TOTP.

## Usage

```shellsession
$ # Install module
$ go get "github.com/KEINOS/go-totp"
```

```go
// Use package
import "github.com/KEINOS/go-totp/totp"
```

### Basic Usage

```go
// import "github.com/KEINOS/go-totp/totp"

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
```

- [View it online](https://go.dev/play/p/s7bAGoLY25R) @ Go Playground

```go
//  * You should handle the error in your code.

// ----------------------------------------------------------------------------
//  Generate a new secret key with custom options
// ----------------------------------------------------------------------------
key, err := totp.GenerateKey(Issuer, AccountName,
    // Optional:
    totp.WithAlgorithm(totp.Algorithm("SHA256")),
    totp.WithPeriod(15),
    totp.WithSecretSize(256),
    totp.WithSecretQueryFirst(false),
    totp.WithSkew(5),
    totp.WithDigits(totp.DigitsEight),
)

// ----------------------------------------------------------------------------
//  Major methods of totp.Key object
// ----------------------------------------------------------------------------

// Generate the current passcode.
passcode, err := key.PassCode()

// Validate the received passcode.
ok := key.Validate(passcode)

// Get the image object of QR code with the given fix level.
// Fix level choices are:
//   FixLevel30 = H // 30% error correction
//   FixLevel25 = Q // 25%
//   FixLevel15 = M // 15%
//   FixLevel7  = L // 7%
//   FixLevelDefault = FixLevel15
qrCodeObj, err := key.QRCode(totp.FixLevelDefault)

// Get 100x100 px image of QR code as PNG byte data.
pngBytes, err := qrCodeObj.PNG(100, 100)

// Get the secret key in PEM format text.
pemKey, err := key.PEM()

// Get the secret key in TOTP URI format string.
// The output is equivalent to key.String().
//
// The query parameters of generated URI are sorted except for the "secret"
// parameter which is kept at the top. This avoids a niche reading error of
// Google Authenticator app if the QR code image is generated with other apps.
uriKey := key.URI()

// Retrieve the secret value in various formats.
// ---------------------------------------------

// Get the secret value in Base32 format string.
// This encoding is used in TOTP URI format and is equivalent to
// key.Secret.String().
base32Key := key.Secret.Base32()

// Get the secret value in Base62 format string.
base62Key := key.Secret.Base62()

// Get the secret value in Base64 format string.
// This encoding is used in PEM format.
base64Key := key.Secret.Base64()

// Get the secret value in bytes. This is the raw secret value.
rawKey := key.Secret.Bytes()
```

- [View __more examples__ and advanced usages](https://pkg.go.dev/github.com/KEINOS/go-totp/totp#pkg-examples) @ pkg.go.dev

### ECDH Support

This package supports [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) key agreement protocol for the TOTP secret key generation (deriving TOTP secret from ECDH [shared secret](https://en.wikipedia.org/wiki/Shared_secret)).

```go
// Pre-agreement between Alice and Bob. commonCtx can be any string but consistent
// between Alice and Bob.
commonCurve := ecdh.X25519()
commonCtx := "example.com alice@example.com bob@example.com TOTP secret v1"

// ECDH Key pair generator. Do not expose the private key.
func newECDHKeys(paramCommon ecdh.Curve) (*ecdh.PrivateKey, *ecdh.PublicKey) {
    priv, err := paramCommon.GenerateKey(rand.Reader)
    if err != nil {
        log.Fatal(err, "failed to generate ECDH private key")
    }

    return priv, priv.PublicKey()
}

// Generate a new ECDH key for Alice and Bob and exchange public keys.
alicePriv, alicePub := newECDHKeys(commonCurve)
bobPriv, bobPub := newECDHKeys(commonCurve)

// Generate a new TOTP key for Alice using:
// - Alice's ECDH private key
// - Bob's ECDH public key
// - Alice and Bob's common context string
Issuer := "Example.com"
AccountName := "alice@example.com"

key, err := totp.GenerateKey(Issuer, AccountName,
    totp.WithECDH(alicePriv, bobPub, commonCtx),
)
if err != nil {
    log.Fatal(err)
}

// Alice generates 6 digits of TOTP passcode which should be the same as Bob's.
passcode, err := key.PassCode()
if err != nil {
    log.Fatal(err)
}
```

- [View the full ECDH example with detailed comments](https://pkg.go.dev/github.com/KEINOS/go-totp/totp#example-package-ecdh) | GoDoc @ pkg.go.dev

A shared secret key can be created by exchanging a public ECDH key between two parties. This shared secret key is used to derive the TOTP key. Thus the same TOTP passcode can be shared within the same time period.

This feature is useful when a __shared but ephemeral/volatile secret value (a common TOTP passcode) is required__ to increase security between two parties.

For example, a time-based shared [salt](https://en.wikipedia.org/wiki/Salt_(cryptography)) for hashing or an additional value to generate a shared secret key for [symmetric encryption](https://en.wikipedia.org/wiki/Symmetric-key_algorithm).

The values expire, but the possibilities are endless.

## Contributing

[![go1.24+](https://img.shields.io/badge/Go-1.24+-blue?logo=go)](https://github.com/KEINOS/go-totp/blob/main/.github/workflows/unit-tests.yml#L81 "Supported versions")
[![Go Reference](https://pkg.go.dev/badge/github.com/KEINOS/go-totp.svg)](https://pkg.go.dev/github.com/KEINOS/go-totp/totp "View document")
[![Opened Issues](https://img.shields.io/github/issues/KEINOS/go-totp?color=lightblue&logo=github)](https://github.com/KEINOS/go-totp/issues "opened issues")
[![PR](https://img.shields.io/github/issues-pr/KEINOS/go-totp?color=lightblue&logo=github)](https://github.com/KEINOS/go-totp/pulls "Pull Requests")

Any Pull-Request for improvement is welcome!

- Branch to PR: `main`
- [CONTRIBUTING.md](./.github/CONTRIBUTING.md)
- [CIs](https://github.com/KEINOS/go-totp/actions) on PR/Push: `unit-tests` `golangci-lint` `codeQL-analysis` `platform-tests`
- [Security policy](https://github.com/KEINOS/go-totp/security/policy)
- Help wanted
  - [https://github.com/KEINOS/go-totp/issues](https://github.com/KEINOS/go-totp/issues)

### Test Statuses

[![UnitTests](https://github.com/KEINOS/go-totp/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/unit-tests.yml)
[![PlatformTests](https://github.com/KEINOS/go-totp/actions/workflows/platform-tests.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/platform-tests.yml "Tests on Win, macOS and Linux")

[![golangci-lint](https://github.com/KEINOS/go-totp/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/golangci-lint.yml)
[![CodeQL-Analysis](https://github.com/KEINOS/go-totp/actions/workflows/codeQL-analysis.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/codeQL-analysis.yml)
[![Vulnerability Scan](https://github.com/KEINOS/go-totp/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/govulncheck.yml)

[![codecov](https://codecov.io/gh/KEINOS/go-totp/branch/main/graph/badge.svg?token=JVY7WUeUFz)](https://codecov.io/gh/KEINOS/go-totp)
[![Go Report Card](https://goreportcard.com/badge/github.com/KEINOS/go-totp)](https://goreportcard.com/report/github.com/KEINOS/go-totp)

## License, copyright and credits

- MIT, Copyright (c) 2022- [The go-totp contributors](https://github.com/KEINOS/go-totp/graphs/contributors).
- This Go package relies heavily on support from the `github.com/pquerna/otp` package.
  - [https://github.com/pquerna/otp](https://github.com/pquerna/otp) with [Apache-2.0 license](https://github.com/pquerna/otp/blob/master/LICENSE)
