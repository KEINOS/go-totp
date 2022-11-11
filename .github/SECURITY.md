# Security Policy

## Supported  Versions and Statuses

| Version/Section | Status | Note |
| :------ | :----- | :--- |
| Go 1.15, 1.16 ... latest | [![go1.15+](https://github.com/KEINOS/go-totp/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/unit-tests.yml "Unit tests on various Go versions") | Including Go 1.19 |
| Golangci-lint 1.48.0 or later | [![golangci-lint](https://github.com/KEINOS/go-totp/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/golangci-lint.yml) | |
| Security advisories | [Enabled](https://github.com/KEINOS/go-totp/security/advisories) | |
| Dependabot alerts | [Enabled](https://github.com/KEINOS/go-totp/security/dependabot) | (Viewable only for admins) |
| Code scanning alerts | [Enabled](https://github.com/KEINOS/go-totp/security/code-scanning)<br>[![CodeQL-Analysis](https://github.com/KEINOS/go-totp/actions/workflows/codeQL-analysis.yml/badge.svg)](https://github.com/KEINOS/go-totp/actions/workflows/codeQL-analysis.yml) ||

## Update

- We [check the latest version of `go.mod` every week](https://github.com/KEINOS/go-totp/blob/main/.github/workflows/weekly-update.yml) and update it when it has passed all tests.


## Reporting a Vulnerability, Bugs and etc

- [Issues](https://github.com/KEINOS/go-totp/issues)
  - [![Opened Issues](https://img.shields.io/github/issues/KEINOS/go-totp?color=lightblue&logo=github)](https://github.com/KEINOS/go-totp/issues "opened issues")
  - Plase attach a simple test that replicates the issue.
