# Security Policy

At a minimum, the following measures apply:

1. Unit testing with `race` condition check on various Go versions and platforms (via GitHub Actions).
1. Static code analysis and lint check with [golangci-lint](https://golangci-lint.run/) (via GitHub Actions).
1. Code scanning with [CodeQL](https://codeql.github.com/) (via GitHub Actions).
1. [Dependabot alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts) (via GitHub Security).
1. [Security advisories](https://docs.github.com/en/code-security/security-advisories/repository-security-advisories/about-repository-security-advisories) (via GitHub Security).
1. Keeping the version of `go.mod` up-to-date only if the avove tests pass (via GitHub Actions).

## Supported Versions and Statuses

| Version/Section | Status | Note |
| :------ | :----- | :--- |
| Go 1.22 ... latest | [![go1.22+](https://github.com/KEINOS/go-totp/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/unit-tests.yml "Unit tests on various Go versions") | Including Go 1.22 |
| Golangci-lint v1.57.2 or later | [![golangci-lint](https://github.com/KEINOS/go-totp/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/golangci-lint.yml) | |
| Security advisories | [Enabled](https://github.com/KEINOS/go-totp/security/advisories) | |
| Dependabot alerts | [Enabled](https://github.com/KEINOS/go-totp/security/dependabot) | (Viewable only for admins) |
| Code scanning alerts | [Enabled](https://github.com/KEINOS/go-totp/security/code-scanning)<br>[![CodeQL-Analysis](https://github.com/KEINOS/go-totp/actions/workflows/codeQL-analysis.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/codeQL-analysis.yml) ||

> __Note__: Currently, Go 1.22 is the minimum supported version, which matches the minimum version of the dependent packages and linters. Depending on these versions, the minimum supported version may change in the future. Though, __we encourage you to use the latest version of Go__.

## Fail fast policy and update

- We [check the latest version of `go.mod` every week](https://github.com/KEINOS/go-totp/blob/main/.github/workflows/weekly-update.yml) and update it when it has passed all tests.
- We bump up the minimum supported Go version if the packages used in the project require it.

## Reporting a Vulnerability, Bugs and etc

- [Issues](https://github.com/KEINOS/go-totp/issues)
  - [![Opened Issues](https://img.shields.io/github/issues/KEINOS/go-totp?color=lightblue&logo=github)](https://github.com/KEINOS/go-totp/issues "opened issues")
  - Plase attach a simple test that replicates the issue. It will help us a lot to fix the issue.
  - Issues can be in Japanese and Spanish rather than English if you prefer.
