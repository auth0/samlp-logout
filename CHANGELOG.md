# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [3.1.1](https://github.com/auth0/samlp-logout/compare/v3.1.0...v3.1.1) (2023-12-19)

## [3.1.0](https://github.com/auth0/samlp-logout/compare/v3.1.0...v4.0.0) (2023-12-19)

- Properly calling next() callback when using HTTP-POST bindings

## [3.1.0](https://github.com/auth0/samlp-logout/compare/v3.0.0...v3.1.0) (2021-08-30)

- Do not send empty RelayState fields. This works around a bug in Azure AD.

## [3.0.0](https://github.com/auth0/samlp-logout/compare/v2.3.3...v3.0.0) (2021-02-09)

### ⚠ BREAKING CHANGES

- since 4.0.0, next() callback is properly called with HTTP-POST bindings

- newer mochas drop support for older node versions and only support 10 upwards

- fix npm audit warnings for cheerio, mocha & xml-crypto ([02bed18](https://github.com/auth0/samlp-logout/commit/02bed1893d44879e8a1ed306dd1d460df4d6554f))
