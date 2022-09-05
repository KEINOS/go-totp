# go-totp

`go-totp` is a simple Go package to implement [Timebased-One-Time-Password](https://en.wikipedia.org/wiki/Time-based_one-time_password) authentication functionality, a.k.a. `TOTP`, to the Go app.

> __Note__ This is a wrapper of the awesome [`github.com/pquerna/otp`](https://github.com/pquerna/otp) package to facilitate the use of TOTP.

```go
go get "github.com/rodrigodiez/go-totp"
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
    valid, err := key.Validate(passcode)
    if err != nil {
        log.Fatal(err)
    }

    if valid {
        fmt.Println("Passcode is valid")
    }

    // Output: Passcode is valid
}
```

- [View more examples and advanced usages](https://pkg.go.dev/github.com/KEINOS/go-totp#pkg-examples) @ pkg.go.dev

## Statuses

[![UnitTests](https://github.com/KEINOS/go-totp/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/unit-tests.yml)
[![golangci-lint](https://github.com/KEINOS/go-totp/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/golangci-lint.yml)
[![CodeQL-Analysis](https://github.com/KEINOS/go-totp/actions/workflows/codeQL-analysis.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/codeQL-analysis.yml)
[![PlatformTests](https://github.com/KEINOS/go-totp/actions/workflows/platform-tests.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/platform-tests.yml "Tests on Win, macOS and Linux")

[![codecov](https://codecov.io/gh/KEINOS/go-totp/branch/main/graph/badge.svg?token=JVY7WUeUFz)](https://codecov.io/gh/KEINOS/go-totp)
[![Go Report Card](https://goreportcard.com/badge/github.com/KEINOS/go-totp)](https://goreportcard.com/report/github.com/KEINOS/go-totp)

## Contributing

[![go1.15+](https://img.shields.io/badge/Go-1.15+-blue?logo=go)](https://github.com/KEINOS/go-totp/blob/main/.github/workflows/unit-tests.yml#L81 "Supported versions")
[![Go Reference](https://pkg.go.dev/badge/github.com/KEINOS/go-totp.svg)](https://pkg.go.dev/github.com/KEINOS/go-totp/ "View document")
[![Opened Issues](https://img.shields.io/github/issues/KEINOS/go-totp?color=lightblue&logo=github)](https://github.com/KEINOS/go-totp/issues "opened issues")
[![PR](https://img.shields.io/github/issues-pr/KEINOS/go-totp?color=lightblue&logo=github)](https://github.com/KEINOS/go-totp/pulls "Pull Requests")

Any Pull-Request for improvement is welcome!

- Branch to PR: `main`
- [CIs](https://github.com/KEINOS/go-totp/actions) on PR/Push: `unit-tests` `golangci-lint` `codeQL-analysis` `platform-tests`
- [Security policy](https://github.com/KEINOS/go-totp/security/policy)

## License, copyright and credits

- MIT, Copyright (c) 2022 [KEINOS and the go-totp contributors](https://github.com/KEINOS/go-totp/graphs/contributors).
- This Go package relies heavily on support from the `github.com/pquerna/otp` package.
  - [https://github.com/pquerna/otp](https://github.com/pquerna/otp) with [Apache-2.0 license](https://github.com/pquerna/otp/blob/master/LICENSE)
