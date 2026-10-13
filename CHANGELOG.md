# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - unreleased

### Security

- Builders refuse values with CR, LF, NUL, DEL or any character outside tab, space and
  visible ASCII, so a value can no longer inject a header line.

### Added

- `strict=True` on every parser: the RFC 9110 grammar (obsolete line folding, controls,
  unterminated quoted-strings, trailing text, params outside a challenge, a tab after the
  scheme, duplicate names, realm as a token) and the Basic, Bearer and Digest rules raise
  `AuthError` with the reason and offset.
- `parse_auth_info` and `build_auth_info` for Authentication-Info and
  Proxy-Authentication-Info.
- `encode_basic` and `decode_basic` (RFC 7617), `build_bearer_challenge` (RFC 6750),
  `encode_ext_value` and `decode_ext_value` (RFC 8187), `select_challenge`.
- `parse_challenges` accepts several field lines.
- The `authchallenge` command and `python -m authchallenge`: JSON output, `--strict` lint.

### Changed

- Of two params with the same name the first wins (it was the last).
- Obsolete line folding is read as a space instead of yielding nothing.
- A token68 challenge never collects params that follow it.
- Builders quote `realm` always, every Basic and Bearer param, and the Digest params RFC
  7616 lists; Digest `stale`, `algorithm`, `qop` (credentials) and `nc` are written bare.
- Tolerant parsing reads a bare line break (not obsolete folding) as the end of a field
  line, and drops a token value cut short by a stray character instead of truncating it.
- `decode_ext_value` refuses text that decodes to control characters; `encode_basic` and
  `decode_basic` accept only UTF-8 and ISO-8859-1.
- Builders refuse names that differ only in case and whatever strict parsing refuses,
  including a Basic challenge without realm and incomplete Digest params.

## [0.1.0]

- Parse WWW-Authenticate and Proxy-Authenticate headers into a list of challenges, with
  multi-challenge comma disambiguation, token68 and quoted auth-params (RFC 7235).
- Parse Authorization and Proxy-Authorization credentials into a scheme with token68 or
  auth-params.
- Build challenge and credentials strings back, quoting values only when required.
- Typed, zero dependencies, `py.typed`.
