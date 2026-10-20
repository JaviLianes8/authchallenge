# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-20

The public API is now stable: the fifteen names of `__all__`, their signatures,
parameter names and defaults, the `AuthError` type and the documented behaviour of
tolerant and strict parsing will only change in a new major version.

### Changed

- Arguments of the wrong type raise `TypeError` with the argument's name. In 0.2.0
  the builders raised `AuthError` for a scheme, token68, param name or value that was
  not a `str`, and the other functions leaked `AttributeError` or a `TypeError` from
  deep inside (for example `parse_challenges(b"...")`, `decode_basic(None)`,
  `select_challenge([...], 1)`, `build_challenge("X", [("a", "b")])`). This covers
  `select_challenge` given something that is not iterable or a `Challenge` whose scheme
  is not a `str`, and `decode_basic` given `Credentials` whose token68 is not a `str`.
- `parse_challenges` and `parse_auth_info` refuse `bytes` with a `TypeError` that says
  to decode them as latin-1.
- Error messages quote at most 40 characters of the input, and never a token68:
  `decode_basic` and the builders used to repeat the whole base64 credentials (a
  password) or a megabyte of input in the message. Strict errors about credentials quote
  none of their text (no param name, which may be a mangled secret), and say
  "outside the credentials" rather than "outside a challenge". `decode_basic` no longer
  quotes what it read as the scheme of a `str` value.
- Basic errors chain no `UnicodeError` or base64 error: those held the whole
  `user:password` and every traceback printed them.
- `encode_ext_value` raises `AuthError` for text with a lone surrogate instead of
  `UnicodeEncodeError`, and for text with a control character (C0, DEL or C1), which
  `decode_ext_value` and strict Digest `username*` refuse; 0.2.0 encoded it. Whatever
  it returns now decodes back to the same text.
- `decode_ext_value` (and strict Digest `username*`) refuse a language that is not an
  RFC 5646 language tag, such as `UTF-8'1'abc`; 0.2.0 accepted any letters, digits and
  hyphens there.
- A Basic charset with a NUL character raises `AuthError` instead of `ValueError`.
- The command line reads stdin as octets decoded as latin-1, as the library documents
  for received field values, instead of the locale's encoding, so its verdict on
  obs-text no longer depends on the platform. Only LF (with an optional CR) ends a line:
  form feed, vertical tab, U+0085 and the other Unicode line breaks stay in the value.
- `repr(Credentials(...))` shows `token68=<hidden>`, so logging parsed credentials does
  not log the secret; the `token68` attribute is unchanged.
- `AuthError`, `Challenge` and `Credentials` report `authchallenge` as their module.
- `build_challenge` and `build_authorization` with `params=[]` (or another empty value
  that is not a mapping) raise `TypeError` instead of building a bare scheme.

### Fixed

- Strict `parse_authorization` refuses a comma or tab right after the scheme of
  credentials whose scheme has no rules of its own, such as `Newauth,` or `Newauth\t ,`:
  credentials are one element, not a list, so the empty list elements a challenge may
  hold do not apply. 0.2.0 accepted them. Basic and Bearer credentials such as `Basic,`
  or `Basic\tdTpw` were already refused; `Basic,` now gets the clearer message.
- Strict `parse_challenges` refuses params after a scheme followed by a tab and then a
  space before the comma (`Newauth\t ,x=1`): RFC 9110 asks for a space first. 0.2.0
  accepted it.
- The command line reads a header dump with folded lines in linear time; 0.2.0 took
  seconds on a megabyte of continuation lines.
- `decode_basic` (and strict Basic credentials) refuse base64 whose length is not a
  multiple of four or that ends in more than two `=`, on every Python. Some CPython 3.10
  and 3.11 releases accept surplus padding, so there 0.2.0 decoded
  `Basic QWxhZGRpbjpvcGVu=` (3.10.19, 3.11.5) or `Basic dTpw====` (3.11.5, 3.11.17);
  3.12 and later already refused them.

### Added

- Runnable examples in every public docstring, run as doctests, and a GUIDE whose
  examples run as tests.
- Contracts: pinned signatures, seeded property tests against a recognizer written from
  the RFC 9110 grammar, linear time on hostile input, curl, httpx, requests, werkzeug and
  urllib as live oracles, the RFC 8187 text, and PyPI 0.2.0 as an oracle for upgrades.

## [0.2.0] - 2026-10-19

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

## [0.1.0] - 2026-10-11

Not published on PyPI.

- Parse WWW-Authenticate and Proxy-Authenticate headers into a list of challenges, with
  multi-challenge comma disambiguation, token68 and quoted auth-params (RFC 7235).
- Parse Authorization and Proxy-Authorization credentials into a scheme with token68 or
  auth-params.
- Build challenge and credentials strings back, quoting values only when required.
- Typed, zero dependencies, `py.typed`.
