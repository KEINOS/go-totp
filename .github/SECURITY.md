# Security Policy

At a minimum, the following measures apply:

1. Unit testing with `race` condition check on various Go versions and platforms (via GitHub Actions).
1. Static code analysis and lint check with [golangci-lint](https://golangci-lint.run/) (via GitHub Actions).
1. Code scanning with [CodeQL](https://codeql.github.com/) (via GitHub Actions).
1. Vulnerability scanning with [govulncheck](https://go.dev/blog/vuln) (via GitHub Actions).
1. [Dependabot alerts](https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts) (via GitHub Security).
1. [Security advisories](https://docs.github.com/en/code-security/security-advisories/repository-security-advisories/about-repository-security-advisories) (via GitHub Security).
1. Keeping the version of `go.mod` up-to-date only if the above tests pass (via GitHub Actions).

## Supported Versions and Statuses

| Version/Section | Status | Note |
| :------ | :----- | :--- |
| ![](https://img.shields.io/github/go-mod/go-version/KEINOS/go-totp) ... latest | [![go1.22+](https://github.com/KEINOS/go-totp/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/unit-tests.yml "Unit tests on various Go versions") |  |
| Latest Golangci-lint | [![golangci-lint](https://github.com/KEINOS/go-totp/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/golangci-lint.yml) | |
| Security advisories | [Enabled](https://github.com/KEINOS/go-totp/security/advisories) | |
| Dependabot alerts | [Enabled](https://github.com/KEINOS/go-totp/security/dependabot) | (Viewable only for admins) |
| Code scanning alerts | [Enabled](https://github.com/KEINOS/go-totp/security/code-scanning)<br>[![CodeQL-Analysis](https://github.com/KEINOS/go-totp/actions/workflows/codeQL-analysis.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/codeQL-analysis.yml) ||

## Fail fast policy and update

- We [check the latest version of `go.mod` every week](https://github.com/KEINOS/go-totp/blob/main/.github/workflows/weekly-update.yml) and update it when it has passed all tests.
- We bump up the minimum supported Go version if the packages used in the project require it.

## Reporting a Vulnerability, Bugs and etc

- [Issues](https://github.com/KEINOS/go-totp/issues)
  - [![Opened Issues](https://img.shields.io/github/issues/KEINOS/go-totp?color=lightblue&logo=github)](https://github.com/KEINOS/go-totp/issues "opened issues")
  - Plase attach a simple test that replicates the issue. It will help us a lot to fix the issue.
  - Issues can be in Japanese and Spanish rather than English if you prefer.
