# authchallenge 1.0.0 certification report

The 1.0.0 certification bar (19 items) applied to authchallenge. PyPI has 0.2.0
(uploaded 2026-10-19), which is byte for byte the `main` branch at d087552 (the wheel's
modules compared with the tree), so every change listed here is a change against the
PyPI release.

Progress:
- [x] Branch `release/1.0.0` created from `main` (d087552, same code as PyPI 0.2.0)
- [x] Baseline gates on 0.2.0
- [x] API review and 1.0.0 changes (item 1)
- [x] Errors, typing, docstrings and doctests (items 2 to 5)
- [x] Ground truth: specifications fetched live, live oracles (item 7)
- [x] Contract, fuzz and hostile input (items 6, 9)
- [x] Docs: README, GUIDE, CHANGELOG (items 11, 12)
- [x] Packaging, e2e and upgrade from PyPI 0.2.0, every Python (items 8, 10, 13, 14)
- [x] Author mutation round (item 18)
- [x] Gates (item 15), final run
- [x] PR and trace guard CLEAN
- [ ] Five QA lenses report PASS (item 19)
- [ ] Independent reviewer reports PASS (item 16)
- [ ] Merge and publish (item 17), by the maintainer

## Scorecard

| # | Item | Result |
| --- | --- | --- |
| 1 | Public API reviewed for stability | PASS: 15 names kept from 0.2.0 and pinned; every change in the CHANGELOG |
| 2 | `__all__` exact, no private imports in docs | PASS |
| 3 | Docstrings with runnable examples, doctests | PASS: doctests, README and GUIDE examples run as tests |
| 4 | Typed end to end | PASS: `mypy --strict src tests`, `py.typed`, a consumer checked against the install |
| 5 | Typed, documented, bounded errors | PASS: `AuthError` (a `ValueError`), `TypeError` for wrong types, 40-character quotes, no token68 |
| 6 | Contract tests of every public name | PASS |
| 7 | Real ground truth | PASS: 8 fetched sources with a hash manifest, greenbytes, curl, httpx, requests, werkzeug, urllib, PyPI 0.2.0 |
| 8 | Real e2e from the wheel | PASS: wheel in a fresh venv, CLI by subprocess, upgrade in place from PyPI 0.2.0 |
| 9 | Seeded fuzz, no crash, hang or blowup | PASS |
| 10 | Supported Pythons | PASS: CPython 3.10 to 3.14 and 3.14 free-threaded |
| 11 | README and `twine check` | PASS |
| 12 | Dated CHANGELOG section | PASS: 1.0.0, 2026-10-20 |
| 13 | pyproject 1.0.0, Production/Stable | PASS |
| 14 | sdist and wheel contents | PASS |
| 15 | Gates each exit 0 | PASS: see Gates |
| 16 | Independent reviewer | pending |
| 17 | PR and trace guard | PR from `release/1.0.0`, trace guard CLEAN; merge and publish left to the maintainer |
| 18 | Contracts bite (mutations) | PASS: 43 author mutants, all killed |
| 19 | Five independent QA lenses | pending |

## Baseline on 0.2.0 (before any change)

At d087552 on this PC, CPython 3.13.2: `ruff format --check .`, `ruff check .` and
`mypy --strict src tests` exit 0; `pytest` 242 passed, 1 skipped (the installed-wheel
test, which needs `AUTHCHALLENGE_E2E=1`), with the eight reference files fetched.

Defects found in 0.2.0 by probing every public name with wrong types, huge input and
hostile input, each reproduced before it was fixed:

- Wrong argument types leaked `AttributeError` (`decode_basic(5)`,
  `select_challenge([...], 5)`, `build_challenge("X", [("a", "b")])`,
  `parse_auth_info("a=b", scheme=5)`) or an unrelated `TypeError` from deep inside
  (`parse_challenges(b"...")` said "expected string or bytes-like object, got 'int'"),
  while the builders raised `AuthError` for a non-`str` value.
- `decode_basic("Basic <base64>!")` and `decode_basic("<base64>")` put the whole base64
  credentials, a password, in the message; `build_authorization` quoted an invalid token68.
- Messages repeated the input in full: a 100 KB ext-value, scheme, param name or Digest
  value gave a 100 KB to 150 KB message.
- `encode_ext_value("\ud800")` raised `UnicodeEncodeError` instead of `AuthError`.
- `repr` of parsed `Credentials` printed the token68 (a password or a bearer token).
- Strict `parse_authorization` accepted `Basic,` and `Foo\t ,`: credentials are one
  element, so a comma or tab right after the scheme breaks the grammar (found by the
  grammar recognizer of `tests/test_fuzz.py`).
- No public docstring had a runnable example, there was no GUIDE, and the README linked
  LICENSE relatively, which breaks on PyPI.

## API review (item 1)

Kept: the fifteen public names of 0.2.0 with their signatures, parameter names and
defaults, now pinned by `tests/test_contract_api.py`. `Challenge` and `Credentials` keep
their three fields and stay frozen dataclasses (not hashable, since `params` is a dict,
which is documented). Changed, all in the CHANGELOG: `TypeError` for wrong argument
types, bytes refused with a hint to decode as latin-1, bounded messages that never quote
a token68, `AuthError` for a lone surrogate in `encode_ext_value`, `Credentials` hiding
its token68 in `repr`, the public classes reporting `authchallenge` as their module, and
the strict credentials fix. Internal: the parser split in two (`_drafts.py` groups list
elements, `_parse.py` holds the public functions) to keep every file under 200 lines with
the new examples.

## Ground truth (item 7)

Fetched again on 2026-10-20 (UTC) by `scripts/fetch_upstream.py` into the ignored
`tests/upstream` folder; all eight files matched the size and sha256 recorded in
`tests/upstream/MANIFEST.json` on 2026-10-13: RFC 9110, RFC 9112, RFC 7235, RFC 7617,
RFC 7616, RFC 6750, RFC 8187 (https://www.rfc-editor.org/rfc/rfcNNNN.txt) and the
greenbytes WWW-Authenticate test cases (http://test.greenbytes.de/tech/tc/httpauth/).
Nothing fetched is committed or shipped.

- RFC 9110, 7617, 7616 and 6750 (`tests/test_sources.py`): `tchar` and `token68` read from
  the ABNF, the section 11.6.1 example, the Basic vectors and challenges, the Digest
  quoting lists and examples, the Bearer character sets, examples and error codes.
- RFC 8187 (`tests/test_spec_rfc8187.py`, new): `attr-char` and `mime-charsetc` read from
  the ABNF and checked character by character; the section 3.2.3 examples cut from the
  text and decoded.
- greenbytes (`tests/test_greenbytes.py`): every case in both modes.
- The RFC 9110 grammar as an independent recognizer (`tests/test_fuzz.py`, written by hand
  from the ABNF of sections 5.6.1, 5.6.2, 5.6.4 and 11, sharing no code with the library):
  strict challenges, credentials and Authentication-Info accept exactly what it accepts
  on 18,000 hostile strings per field.
- Live oracles run in this session (`tests/test_oracles.py`, `tests/test_oracle_curl.py`):
  curl 8.19.0 (Windows build) sends Basic and Bearer credentials and answers our Digest
  challenge from a local server; httpx 0.27.0 answers our Digest challenge; requests
  2.32.3 agrees with `encode_basic` on 4,000 latin-1 pairs and answers our challenge;
  werkzeug 3.1.3 reads 2,000 built challenges and credentials to the same values, and the
  standard library's urllib splits 2,000 built Digest challenges the same way and answers
  one. Findings, asserted precisely: requests and urllib quote the Digest `algorithm`,
  and curl's Windows build quotes `qop`, which RFC 7616 section 3.4 tells senders not to
  do (strict mode names it, tolerant mode reads the same values); werkzeug writes `realm`
  as a token, which RFC 9110 section 11.5 forbids senders.
- PyPI 0.2.0 as an oracle (`tests/test_upgrade.py`, `AUTHCHALLENGE_V02`): 80,000 parser
  calls and 50,000 builder and codec calls give the same results and error families;
  the documented changes are checked case by case.

## Fuzz and hostile input (item 9)

`tests/test_fuzz.py`, seeds 1, 20261019 and 987654321: strict challenges, credentials and
Authentication-Info accept exactly what the hand-written RFC 9110 recognizer accepts
(6,000 strings per seed and field), tolerant mode never raises and agrees with strict mode
where strict accepts, built headers read back strictly to the same values, the codecs round
trip and refuse garbage with `AuthError` only. `tests/test_hostile.py`: 17 input shapes
(commas, folds, line breaks, runs of spaces and tabs, schemes, high octets...) through all
six parser calls stay linear at eight times the input, many field lines, megabyte input to
the codecs, a large dump through the command line, and no recursion.

## Author mutation round (item 18)

40 mutants over every module, each applied alone to a fresh clone of the pushed branch on
another machine and run against the full suite: all 40 killed. Three more on the padding
fix and the strict tab rule, run on the interpreters where they can change behaviour, are
killed too. The table is in
[CERT-1.0-MUTANTS.md](https://github.com/JaviLianes8/authchallenge/blob/main/CERT-1.0-MUTANTS.md).

## Packaging, e2e and Pythons (items 8, 10, 13, 14)

The interpreter matrix found a real defect: on some CPython 3.10 and 3.11 releases
`base64.b64decode(validate=True)` accepts surplus padding, so `decode_basic` decoded
`Basic QWxhZGRpbjpvcGVu=` (and 0.2.0 does the same there). The length check before decoding
gives one answer on every version; the CHANGELOG lists it under Fixed, the contracts are in
`tests/test_contract_edges.py`, and the 0.2.0 oracle now asks the running Python's base64
module whether 0.2.0 could have accepted a token.

- At 23b8908, from a fresh clone on Elena's PC: `python -m build`, `twine check --strict`
  (both PASSED), wheel 25,251 bytes and sdist 53,479 bytes. The wheel holds the package,
  `py.typed`, the entry point and LICENSE; the sdist holds the sources, tests, scripts,
  docs, LICENSE and `tests/upstream/MANIFEST.json`, and no fetched file, report or scratch
  file.
- `AUTHCHALLENGE_E2E=1 AUTHCHALLENGE_E2E_PYPI=1` full suite (CPython 3.14.2, 0.2.0 oracle
  present): the e2e test builds the wheel, installs PyPI 0.2.0 in a fresh venv, upgrades it
  in place to the wheel, drives the installed package from an empty folder with `-I`, type
  checks a consumer with `mypy --strict` against the install, and runs the CLI as
  `python -m authchallenge` and as the `authchallenge` script. 415 passed, 1 skipped (curl
  there refuses Digest through the system; on this PC curl answers it).
- The wheel installed in a fresh venv per interpreter and the sdist's own suite run with
  `src` removed (fetched sources, the 0.2.0 oracle, httpx 0.27.0, requests 2.32.3 and
  werkzeug 3.1.3 present): CPython 3.10.22, 3.11.17, 3.12.15, 3.13.16, 3.14.8 and 3.14.8
  free-threaded, 398 passed and 2 skipped each (the opt-in e2e test and curl's Digest).
  3.8 and 3.9 are below `requires-python`. Heavy runs go to the other machines, so these
  interpreters were installed there with uv; this PC holds 3.10.19, 3.11.5, 3.12.12, 3.13.2
  and 3.14.2 (with and without the GIL), and 3.11.5 and 3.13.2 ran the changed tests here.

## Gates (item 15)

At 23b8908 from a fresh clone on Elena's PC, each command on its own: `ruff format --check .`,
`ruff check .`, `mypy --strict src`, `mypy --strict src tests` and `pytest` (as above)
exit 0.

## QA lenses (item 19)

Five independent lenses: a (API and docs), b (correctness and ground truth), c
(adversarial and robustness), d (packaging and real e2e), e (contract strength).

### Round 1 (at aa61317)

Every finding was accepted and fixed; none is disputed. Each behaviour bug first got a
contract that failed on aa61317, then the fix. Fixed in d0d77ef.

| Lens | Finding | Change |
| --- | --- | --- |
| a F1 | `encode_ext_value` encoded controls that `decode_ext_value` refuses | It raises `AuthError` for C0, DEL and C1; a seeded property test checks `decode(encode(s)) == s` for every accepted text |
| a F2, c F6 | `select_challenge(None, ...)`, a `Challenge` with a non-`str` scheme and `Credentials` with a non-`str` token68 leaked bare `TypeError` or `AttributeError` | `TypeError` naming the argument |
| a F3 | The CHANGELOG said 0.2.0 accepted `Basic,` and a tab after Basic | Reworded after running PyPI 0.2.0: the change is for schemes without rules of their own (`Newauth,`, `Newauth\t ,`) |
| a F4 | The `AuthError` docstring promised an offset for all strict errors | Aligned with the GUIDE: the offset is given for grammar errors |
| a F5 | Strict credentials errors said "outside a challenge" | They say "outside the credentials" |
| a F6 | The 0.1.0 CHANGELOG section had no date | Dated 2026-10-11 (commit df66c3f), marked as not published on PyPI |
| b F1 | Strict challenges took params after `scheme<TAB>,` | Only a space opens the params (RFC 9110 section 11.3). `Newauth\t, x=1` was a regression of this branch (0.2.0 refused it); `Newauth\t ,x=1` was accepted by 0.2.0 and is in the CHANGELOG |
| b F2 | The ext-value language was any `[A-Za-z0-9-]*` | Checked against the RFC 5646 section 2.1 Language-Tag grammar (langtag, privateuse, grandfathered); linear on 80,000 subtags |
| c F1 | The CLI joined folded lines in quadratic time | Continuation lines are collected and joined once; a ratio test pins linear time |
| c F2 | Basic errors chained a `UnicodeError` holding `user:password` | The error is raised outside the handler: no cause, no context but our own `AuthError` |
| c F3 | A charset with NUL raised `ValueError` | `AuthError` |
| c F4 | `decode_basic` quoted a would-be scheme swallowing the base64; strict credentials quoted param names cut from a token68 | No quote of the scheme read from a `str`; credentials errors quote no param name |
| c F5, d F1 | The CLI split on every Unicode line break and decoded stdin with the locale codec | Stdin is read as octets decoded as latin-1; only LF (with an optional CR) ends a line |
| e F1 | No test of the CLI field mapping | A dump with all six field names checks each kind |
| e F2 | No secret test on the base64 decode failure branch | Three calls added to `SECRET_CALLS` |
| e F3, e F4 | Digest quoting checked only with the fetched RFC text | `tests/test_digest_quoting.py` always runs, with the lists written by hand from RFC 7616 sections 3.3 to 3.5, building and refusing the wrong quoting of each name |

Mutants run against the new contracts, each applied alone (all killed): the Proxy-Authorization
kind set to challenges; the token68 added to the base64 error; `opaque` dropped from the
quoted challenge list; `nc` dropped from the bare credentials list; the params opened by any
whitespace; the language check skipped; `ValueError` no longer caught for the charset; stdin
decoded as UTF-8; credentials errors quoting the param name.

PyPI 0.2.0 as an oracle (`tests/test_upgrade.py`) lists the new changes: control characters in
`encode_ext_value`, a bad ext-value language, the tab before the comma and the NUL charset.

Gates at d0d77ef, from a fresh clone on Elena's PC (CPython 3.14.2, the fetched sources and the
0.2.0 oracle present): `ruff format --check .`, `ruff check .`, `mypy --strict src`,
`mypy --strict src tests` and `pytest` exit 0 (501 passed, 8 skipped: the opt-in e2e and the
live oracles whose tools are not installed there).

### Round 2 (at 64215e6)

Lenses a, c and e reported; every finding was accepted and fixed, none is disputed. Each
behaviour bug first got a contract in `tests/test_qa_round2.py` that failed on 64215e6, then
the fix. Fixed in d59b7d7 and 25daa85.

| Lens | Finding | Change |
| --- | --- | --- |
| a N1, c N2 | Strict errors on Digest `username*` quoted the ext-value, its language or its charset; a bad octet in credentials quoted the character | `username*` errors say "the Digest username* parameter is not a valid ext-value"; a bad octet in credentials gives only its offset ("a character a field value cannot hold"); challenges keep the character. A seeded sweep of 4,000 hostile credentials checks that no strict error carries a marker planted in the input |
| c N1, e N5 | `decode_basic(Credentials)` quoted the scheme, which holds the base64 when a value without a scheme was parsed tolerantly | Never quoted: "not Basic credentials: the scheme is not Basic", pinned for `Credentials` with a base64 scheme and with `Digest` |
| c N3 | A `TypeError` raised while iterating the caller's iterable became a message about the argument type (`select_challenge`, and `each_line` behind `parse_challenges` and `parse_auth_info`) | Only `iter()` is guarded; the caller's own `TypeError` propagates |
| e N1 | No test that strict credentials errors do not name a duplicate param | The exact message `duplicate auth-param at offset 21` is pinned, and duplicates with a secret-looking name are in the sweep |
| e N2 | No CLI test of a folded line starting with a tab | Header-dump test with a tab continuation |
| e N3 | No CLI test that only SP and HTAB are whitespace | A first line of VT, FF or NEL reads as a plain line; a plain line ending in FF fails `--strict` at offset 15 |
| e N4 | No test of three extlang subtags or a 4-letter language | `zh-abc-def`, `zh-abc-def-ghi` and `abcd` accepted, `zh-abc-def-ghi-jkl` refused |

Mutants run against the new contracts, each applied alone (all killed): the duplicate-param
name without the credentials guard; obs-fold on space only; `strip()` for the first line;
`strip()` for plain lines; one extlang at most; a language of 5 to 8 letters; the scheme
quoted again in `decode_basic`; the `username*` error re-raised as is; the bad-octet message
with the character for credentials; `list()` of the iterable inside the type guard.

Gates on Elena's PC (CPython 3.14.2, a copy of the commit with the fetched sources). At
d59b7d7 one test failed, `tests/test_schemes.py`, which pinned the old quoted `username*`
message; 25daa85 pins the new one. At 25daa85 `ruff format --check .`, `ruff check .`,
`mypy --strict src`, `mypy --strict src tests` and `pytest` exit 0 (539 tests collected, 11
skipped: the opt-in e2e, the 0.2.0 oracle, and the live oracles whose tools are not installed
there).

### Round 3 (at c5de815)

Lens e reported two gaps in the contracts (no behaviour bug); both were accepted and fixed,
none is disputed. The library code and the public behaviour are unchanged, so the CHANGELOG
is unchanged. Fixed in e3a10f8 (`tests/test_qa_round3.py`).

| Lens | Finding | Change |
| --- | --- | --- |
| e F1 | Nothing checked the exception chain of the Digest `username*` error: without `from None` the printed traceback of `build_authorization` showed the inner ext-value error quoting the user name | The full printed traceback (`traceback.format_exception`) of `build_authorization` with two bad `username*` values and of strict `parse_authorization` is checked: the message, `__suppress_context__` and no user name |
| e F2 | The `TypeError` of `parse_challenges`, `parse_auth_info` and `select_challenge` for a non-iterable argument was not pinned: quoting the argument or dropping `from None` stayed green | With `7**300` the exact messages `expected a str or an iterable of str, not int` and `challenges must be an iterable of Challenge, not int` are pinned, with `__suppress_context__` and no digits of the number in the printed traceback |

Mutants run against the new contracts, each applied alone on this PC (all killed): the
`username*` re-raise without `from None`; the `each_line` type error without `from None`; the
`each_line` type error quoting `value!r`; the `select_challenge` type error without
`from None`; the `select_challenge` type error quoting `challenges!r`.

Gates on Elena's PC (CPython 3.14.2, a copy of the tree with the new tests): `ruff format
--check .`, `ruff check .`, `mypy --strict src` and `pytest` exit 0; `mypy --strict src tests`
exits 0 on this PC.
