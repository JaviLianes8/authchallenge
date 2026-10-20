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
trip and refuse garbage with `AuthError` only. `tests/test_hostile.py`: eleven input shapes
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

- At 1d595e7, from a fresh clone on the laptop: `python -m build`, `twine check --strict`
  (both PASSED), wheel 25,251 bytes and sdist 53,485 bytes. The wheel holds the package, `py.typed`,
  the entry point and LICENSE; the sdist holds the sources, tests, scripts, docs, LICENSE
  and `tests/upstream/MANIFEST.json`, and no fetched file, report or scratch file.
- `AUTHCHALLENGE_E2E=1 AUTHCHALLENGE_E2E_PYPI=1` full suite (CPython 3.14.6): the e2e test
  builds the wheel, installs PyPI 0.2.0 in a fresh venv, upgrades it in place to the wheel,
  drives the installed package from an empty folder with `-I`, type checks a consumer with
  `mypy --strict` against the install, and runs the CLI as `python -m authchallenge` and as
  the `authchallenge` script. 411 passed and 1 skipped (curl there refuses Digest through
  the system); the 0.2.0 oracle tests were re-run separately with the right folder.
- The wheel installed in a fresh venv per interpreter and the sdist's own suite run with
  `src` removed, fetched sources, httpx 0.27.0, requests 2.32.3, werkzeug 3.1.3 present:
  CPython 3.10.22, 3.11.17, 3.12.15, 3.13.16, 3.14.8 and 3.14.8 free-threaded, 398 passed
  and 2 skipped each (the opt-in e2e test and curl's Digest). The 0.2.0 oracle and the edge
  contracts (32 tests) passed on each of them. The same interpreters ran the earlier head
  on Elena's PC. 3.8 and 3.9 are below `requires-python`.

## Gates (item 15)

At 1d595e7 from a fresh clone on the laptop, each command on its own: `ruff format --check .`,
`ruff check .`, `mypy --strict src` and `mypy --strict src tests` exit 0, and `pytest`
passes as above.
