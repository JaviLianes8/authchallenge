# authchallenge improvement round

Progress:
- [x] Brainstorm ranked improvements (this file)
- [x] Pin the ground truth: RFC 9110, RFC 9112, RFC 7235, RFC 7617, RFC 7616, RFC 6750, RFC 8187, the greenbytes httpauth test cases
- [x] Scanner rewrite: list grammar, obs-fold, first duplicate wins, token68 never mixed with params, several field lines
- [x] Strict mode: generic grammar of RFC 9110 section 11 with reasons
- [x] Scheme rules: Basic, Bearer and Digest checks shared by strict parsing and building
- [x] Safe builder: no CR, LF or other controls, sender quoting rules, realm always quoted, duplicate names refused
- [x] Helpers: Basic encode and decode, Bearer challenge, Authentication-Info, ext-value, challenge selection
- [ ] Command line
- [ ] Contracts: pinned sources, greenbytes corpus, README examples, installed wheel
- [ ] Docs and packaging: README, CHANGELOG, metadata, sdist contents
- [ ] Gates: ruff format, ruff check, mypy --strict, pytest
- [ ] Mutation run: removing guarded logic makes the suite fail
- [ ] Independent review findings fixed with regression tests
- [ ] Pull request opened, guard clean

## Starting point

`0.1.0` gives `parse_challenges`, `parse_authorization`, `build_challenge`,
`build_authorization` and two frozen dataclasses. Probed against the sources below:

- `build_challenge("Basic", {"realm": "a\r\nX-Evil: 1"})` writes the CR LF into the
  header: a header injection. DEL, NUL and characters above U+00FF also pass through.
- `Basic realm="foo", realm="bar"` returns the last realm. Parameter names must be unique
  (RFC 9110 section 11.2); most user agents in the greenbytes tests take the first.
- A folded field (`Basic\r\n realm="foo"`) parses to nothing.
- `Newauth abc=, x=y` returns a challenge with a token68 and params at once, which the
  grammar cannot produce.
- `Basic, realm="foo"` and `Basic , realm="foo"` parse alike. The first is a parse error
  (a challenge needs 1*SP before its params), the second is valid (an empty list element).
- Trailing junk is ignored silently: `realm="x" extra`, `qop="auth"x`, an unterminated
  quoted-string. There is no way to ask whether a header is well formed.
- Several field lines cannot be passed; RFC 9110 section 11.6.1 says the field can occur
  more than once.
- `build_challenge("Basic", {"realm": "tok"})` writes `realm=tok`; senders must quote realm
  (section 11.5). `build_challenge("Bearer", {"error": "invalid_token"})` and Digest
  `stale`, `algorithm`, `nc` ignore the quoting rules of RFC 6750 and RFC 7616.
- `parse_authorization("basic QQ== extra")` drops the token silently, and nothing helps
  with Basic user-pass encoding, Bearer error attributes, Authentication-Info or the
  `username*` ext-value of Digest.

## Sources (fetched 2026-10-13)

- RFC 9110, https://www.rfc-editor.org/rfc/rfc9110.txt: section 11 (auth-scheme, token68,
  auth-param, challenge, credentials, realm, the WWW-Authenticate note on the comma
  ambiguity, Authentication-Info), 5.6.1 (lists and empty elements), 5.6.2 (token), 5.6.4
  (quoted-string), 5.5 (field values). Errata, read through
  https://www.rfc-editor.org/errata.json: none of the 14 touches section 11 or 5.6.
- RFC 9112, https://www.rfc-editor.org/rfc/rfc9112.txt: section 5.2, obsolete line
  folding (recipients may replace it with SP, senders must not produce it).
- RFC 7235, https://www.rfc-editor.org/rfc/rfc7235.txt: the history. RFC 9110 obsoletes
  it and appendix B.6 lists no changes; the grammar and the realm rule are the same.
  Erratum 6307 (case of tokens) was rejected.
- RFC 7617, https://www.rfc-editor.org/rfc/rfc7617.txt: realm required, charset only
  `UTF-8`, user-id without colon, no control characters (reported erratum 9174 narrows
  that to the ASCII CTLs), and the two test vectors of sections 2 and 2.1.
- RFC 7616, https://www.rfc-editor.org/rfc/rfc7616.txt: sections 3.3 to 3.5, the quoting
  rules for senders, `nc` as exactly 8 hex digits, username versus `username*`, and the
  examples of section 3.9. Errata 4495, 4897, 5801, 5803, 6704, 7005 and 7936 concern the
  examples' text and digest values, not the header syntax.
- RFC 6750, https://www.rfc-editor.org/rfc/rfc6750.txt: section 3 (at least one
  auth-param, the character sets of scope, error, error_description and error_uri),
  3.1 (error codes) and 2.1 (b64token; reported erratum 5335 says it is token68).
- RFC 8187, https://www.rfc-editor.org/rfc/rfc8187.txt: ext-value for `username*`.
- greenbytes httpauth test cases, http://test.greenbytes.de/tech/tc/httpauth/
  (Last-Modified 27 May 2021): 32 WWW-Authenticate cases with the expected parse after
  post-processing and the ones marked as parse errors.
- None of these files is committed. `tests/upstream/MANIFEST.json` records URL, revision,
  size, sha256 and licence; `scripts/fetch_upstream.py` fetches and checks them into the
  ignored `tests/upstream/` folder, and their tests skip while they are absent.

## Ranked improvements

1. **Safe builder.** Values may hold only HTAB, SP and visible ASCII; anything else raises
   `AuthError` (non-ASCII text goes through an RFC 8187 `name*` ext-value). Names are
   tokens and unique case-insensitively. `realm` is always a quoted-string. Digest follows
   the per-header lists of RFC 7616 (quoted: realm, domain, nonce, opaque, qop, username,
   uri, response, cnonce, nextnonce, rspauth; bare: stale, algorithm, nc, qop in
   credentials and Authentication-Info). Bearer quotes every parameter, as its examples do.
   The built header always passes the strict parser.
2. **Correct tolerant parser.** A scanner over the RFC 9110 list grammar: obs-fold becomes
   SP, empty list elements are skipped, the first duplicate parameter wins, a token68
   challenge never collects params, `Basic , realm=x` is a param list, several field lines
   are accepted as an iterable. Matches every greenbytes case after post-processing.
3. **Strict mode.** `strict=True` raises `AuthError` naming the rule and the offset:
   control characters, obs-fold, unterminated quoted-string, junk after a value, a param
   outside a challenge, token68 followed by more, a tab instead of SP after the scheme,
   duplicate names, realm as a token, an empty field.
4. **Scheme rules.** Shared by strict parsing and building: Basic (realm required, charset
   only UTF-8, token68 credentials that decode to `user-id:password`), Bearer (at least one
   param, the RFC 6750 character sets, b64token credentials), Digest (quoting lists, nc
   format, stale and userhash values, required credential params, username versus
   `username*`, Authentication-Info params required with qop).
5. **Helpers.** `encode_basic` and `decode_basic` with a selectable charset and the RFC 7617
   checks; `build_bearer_challenge` with keyword arguments; `parse_auth_info` and
   `build_auth_info` for Authentication-Info; `encode_ext_value` and `decode_ext_value`;
   `select_challenge` picks the first challenge of a preferred scheme, case-insensitively.
6. **Typed API.** Frozen dataclasses, one error type that is a `ValueError`, keyword-only
   options, `py.typed`.
7. **Command line.** `authchallenge` reads field values or a `curl -sI` dump and prints the
   parsed challenges, credentials and Authentication-Info as JSON; `--strict` lints and
   exits 1 with the reasons. It fits: checking what a server answers is a shell task.
8. **Contracts.** Character sets and grammar read from the pinned RFCs, the RFC examples
   and vectors run through parser and helpers, the greenbytes corpus runs in both modes,
   README examples run, the installed wheel and its console script are driven from an
   empty folder.
9. **Docs and packaging.** README with executed examples and an API table, CHANGELOG,
   keywords and classifiers, an sdist without planning notes or fetched files.

## Out of scope

- Computing Digest responses (hashing A1 and A2): this is a header codec, not an auth
  client. The Digest examples are checked for syntax only.
- PRECIS preparation of Basic user-ids and passwords (RFC 7613): callers normalise.
- Deciding which scheme is most secure: `select_challenge` follows the caller's order.
