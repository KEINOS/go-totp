[![go1.18+](https://img.shields.io/badge/Go-1.18+-blue?logo=go)](https://github.com/KEINOS/go-totp/blob/main/.github/workflows/unit-tests.yml#L81 "Supported versions")
[![Go Reference](https://pkg.go.dev/badge/github.com/KEINOS/go-totp.svg)](https://pkg.go.dev/github.com/KEINOS/go-totp/ "View document")

# go-totp

`go-totp` is a simple Go package to implement [Timebased-One-Time-Password](https://en.wikipedia.org/wiki/Time-based_one-time_password) authentication functionality, a.k.a. `TOTP`, to the Go app.

- [Compatible Authenticator apps](https://github.com/KEINOS/go-totp/wiki/List-of-compatibility) | Wiki @ GitHub

> __Note__ This is a wrapper of the awesome [`github.com/pquerna/otp`](https://github.com/pquerna/otp) package to facilitate the use of TOTP.

## Usage

```go
go get "github.com/KEINOS/go-totp"
```

```go
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
```

- [View it online](https://go.dev/play/p/s7bAGoLY25R) @ Go Playground

```go
// Generate a secret for TOTP (totp.Key object).
key, err := totp.GenerateKey(Issuer, AccountName)

// --------------------------------------------------
//  Basic methods of totp.Key object
// --------------------------------------------------

// Generate the current passcode. Which is a string of
// 6 digit numbers and valid for 30 seconds by default.
passcode, err := key.PassCode()

// Validate the received passcode.
ok := key.Validate(passcode)

// Get 100x100 px image of QR code as PNG byte data.
// FixLevelDefault is the 15% of error correction.
qrCodeObj, err := key.QRCode(totp.FixLevelDefault)
pngBytes, err := qrCodeObj.PNG(100, 100)

// Get the secret key in PEM format text.
pemKey, err := key.PEM()

// Get the secret key in TOTP URI format string.
uriKey := key.URI()

// Get the secret value in Base32 format string.
base32Key := key.Secret.Base32()

// Get the secret value in Base62 format string.
base62Key := key.Secret.Base62()
```

- [View __more examples__ and advanced usages](https://pkg.go.dev/github.com/KEINOS/go-totp/totp#pkg-examples) @ pkg.go.dev

## Statuses

[![UnitTests](https://github.com/KEINOS/go-totp/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/unit-tests.yml)
[![PlatformTests](https://github.com/KEINOS/go-totp/actions/workflows/platform-tests.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/platform-tests.yml "Tests on Win, macOS and Linux")

[![golangci-lint](https://github.com/KEINOS/go-totp/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/golangci-lint.yml)
[![CodeQL-Analysis](https://github.com/KEINOS/go-totp/actions/workflows/codeQL-analysis.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/codeQL-analysis.yml)
[![Vulnerability Scan](https://github.com/KEINOS/go-totp/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/govulncheck.yml)

[![codecov](https://codecov.io/gh/KEINOS/go-totp/branch/main/graph/badge.svg?token=JVY7WUeUFz)](https://codecov.io/gh/KEINOS/go-totp)
[![Go Report Card](https://goreportcard.com/badge/github.com/KEINOS/go-totp)](https://goreportcard.com/report/github.com/KEINOS/go-totp)

## Contributing

[![go1.18+](https://img.shields.io/badge/Go-1.18+-blue?logo=go)](https://github.com/KEINOS/go-totp/blob/main/.github/workflows/unit-tests.yml#L81 "Supported versions")
[![Go Reference](https://pkg.go.dev/badge/github.com/KEINOS/go-totp.svg)](https://pkg.go.dev/github.com/KEINOS/go-totp/ "View document")
[![Opened Issues](https://img.shields.io/github/issues/KEINOS/go-totp?color=lightblue&logo=github)](https://github.com/KEINOS/go-totp/issues "opened issues")
[![PR](https://img.shields.io/github/issues-pr/KEINOS/go-totp?color=lightblue&logo=github)](https://github.com/KEINOS/go-totp/pulls "Pull Requests")

Any Pull-Request for improvement is welcome!

- Branch to PR: `main`
- [CONTRIBUTING.md](./.github/CONTRIBUTING.md)
- [CIs](https://github.com/KEINOS/go-totp/actions) on PR/Push: `unit-tests` `golangci-lint` `codeQL-analysis` `platform-tests`
- [Security policy](https://github.com/KEINOS/go-totp/security/policy)
- Help wanted
    - https://github.com/KEINOS/go-totp/issues

## License, copyright and credits

- MIT, Copyright (c) 2022 [The go-totp contributors](https://github.com/KEINOS/go-totp/graphs/contributors).
- This Go package relies heavily on support from the `github.com/pquerna/otp` package.
  - [https://github.com/pquerna/otp](https://github.com/pquerna/otp) with [Apache-2.0 license](https://github.com/pquerna/otp/blob/master/LICENSE)
