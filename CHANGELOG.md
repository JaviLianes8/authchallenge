# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

- Parse WWW-Authenticate and Proxy-Authenticate headers into a list of challenges, with
  multi-challenge comma disambiguation, token68 and quoted auth-params (RFC 7235).
- Parse Authorization and Proxy-Authorization credentials into a scheme with token68 or
  auth-params.
- Build challenge and credentials strings back, quoting values only when required.
- Typed, zero dependencies, `py.typed`.
