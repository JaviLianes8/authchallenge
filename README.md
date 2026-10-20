# authchallenge

[![Lianes8 Certified](https://lianes8studio.com/certified/lianes8-certified-badge.svg)](https://lianes8studio.com/certified)

Parse and build HTTP authentication headers: `WWW-Authenticate`, `Proxy-Authenticate`,
`Authorization`, `Proxy-Authorization` and `Authentication-Info`, per RFC 9110 with the
rules of Basic (RFC 7617), Digest (RFC 7616) and Bearer (RFC 6750). Typed, zero
dependencies.

## Install

```
pip install authchallenge
```

## Usage

Parse the challenges a server offers. One comma separates both the params of a challenge
and the challenges themselves; the parser tells them apart, keeps a token68 apart from
params, and accepts several field lines:

```python
from authchallenge import parse_challenges, select_challenge

offered = parse_challenges(
    ['Basic realm="simple", Newauth realm="apps", type=1', "Negotiate a87421bff012e83c=="]
)
for challenge in offered:
    print(challenge)
print(select_challenge(offered, "negotiate", "basic").token68)
# Challenge(scheme='Basic', token68=None, params={'realm': 'simple'})
# Challenge(scheme='Newauth', token68=None, params={'realm': 'apps', 'type': '1'})
# Challenge(scheme='Negotiate', token68='a87421bff012e83c==', params={})
# a87421bff012e83c==
```

Parsing is tolerant by default: malformed parts are skipped, obsolete line folding reads
as a space, and of two params with the same name the first wins. With `strict=True`
anything the RFCs forbid raises `AuthError` with the reason:

```python
from authchallenge import AuthError, parse_challenges

print(parse_challenges('Basic realm="a", realm="b"'))
for header in ('Basic, realm="a"', "Basic realm=a", 'Basic realm="a" extra', "Bearer"):
    try:
        parse_challenges(header, strict=True)
    except AuthError as error:
        print(error)
# [Challenge(scheme='Basic', token68=None, params={'realm': 'a'})]
# auth-param 'realm' outside a challenge at offset 7
# the realm parameter must be a quoted-string, in the challenge at offset 0
# unexpected text after the value of 'realm' at offset 16
# a Bearer challenge needs at least one auth-param, in the challenge at offset 0
```

Build headers safely. Values may hold only tab, space and visible ASCII, so a CR LF can
never split the header. Quoting follows the sender rules: realm always, every Basic and
Bearer param, and the Digest lists of RFC 7616. Whatever the builder returns passes the
strict parser:

```python
from authchallenge import AuthError, build_bearer_challenge, build_challenge

digest = {"realm": "api", "qop": "auth", "nonce": "7ypf", "algorithm": "SHA-256"}
print(build_challenge("Digest", digest))
print(build_bearer_challenge(realm="example", error="invalid_token", scope=["read", "write"]))
try:
    build_challenge("Basic", {"realm": "a\r\nSet-Cookie: x=1"})
except AuthError as error:
    print(error)
# Digest realm="api", qop="auth", nonce="7ypf", algorithm=SHA-256
# Bearer realm="example", scope="read write", error="invalid_token"
# the value of 'realm' may hold only tab, space and visible ASCII; send other text as an RFC 8187 ext-value (see encode_ext_value)
```

Credentials, with helpers for Basic and for the RFC 8187 `username*` of Digest. The
vectors come from RFC 7617 sections 2 and 2.1 (https://www.rfc-editor.org/rfc/rfc7617)
and RFC 7616 section 3.9.2 (https://www.rfc-editor.org/rfc/rfc7616):

```python
from authchallenge import decode_basic, decode_ext_value, encode_basic, parse_authorization

print(encode_basic("Aladdin", "open sesame"))
print(decode_basic("Basic dGVzdDoxMjPCow=="))
creds = parse_authorization("Digest username*=UTF-8''J%C3%A4s%C3%B8n%20Doe, realm=\"api\"")
print(creds.scheme, decode_ext_value(creds.params["username*"]))
# Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
# ('test', '123£')
# Digest Jäsøn Doe
```

Authentication-Info, the list of params a server sends after a successful login:

```python
from authchallenge import build_auth_info, parse_auth_info

info = {
    "nextnonce": "47364c23",
    "qop": "auth",
    "rspauth": "6629fae4",
    "cnonce": "0a4f",
    "nc": "00000001",
}
print(build_auth_info(info, scheme="Digest"))
print(parse_auth_info("qop=auth, NC=00000001, nc=2"))
# nextnonce="47364c23", qop=auth, rspauth="6629fae4", cnonce="0a4f", nc=00000001
# {'qop': 'auth', 'nc': '00000001'}
```

## Command line

```
curl -sI https://example.com/private | authchallenge
authchallenge --strict 'Basic realm=foo'
authchallenge --authorization 'Bearer mF_9.B5f-4.1JqM'
```

Values come as arguments or one per stdin line; a header dump on stdin is read for the
authentication fields only (the first non-empty line decides which). The output is JSON.
`--strict` reports the first broken rule of each value on stderr and exits 1.

## API

| Name | Purpose |
| --- | --- |
| `parse_challenges(value, *, strict=False)` | WWW-Authenticate / Proxy-Authenticate, one value or several lines, to a list of `Challenge` |
| `parse_authorization(value, *, strict=False)` | Authorization / Proxy-Authorization to `Credentials` |
| `parse_auth_info(value, *, strict=False, scheme=None)` | Authentication-Info to a dict |
| `build_challenge(scheme, params=None, token68=None)` | One challenge, quoted and checked |
| `build_authorization(scheme, params=None, token68=None)` | Credentials, quoted and checked |
| `build_auth_info(params, *, scheme=None)` | Authentication-Info |
| `build_bearer_challenge(*, realm, scope, error, error_description, error_uri)` | A Bearer challenge per RFC 6750 |
| `encode_basic(user_id, password, *, charset="utf-8")` | `Basic <base64>` per RFC 7617 |
| `decode_basic(credentials, *, charset="utf-8")` | `(user_id, password)` |
| `encode_ext_value(text)` / `decode_ext_value(value)` | RFC 8187 ext-values such as `username*` |
| `select_challenge(challenges, *schemes)` | The first challenge of the most preferred scheme |
| `Challenge`, `Credentials` | Frozen results: `scheme`, `token68`, `params` (names lower-cased); the `repr` of `Credentials` hides the token68 |
| `AuthError` | A `ValueError` raised by builders, codecs and strict parsing; its message quotes at most 40 characters of input and never a token68 |

Arguments of the wrong type (bytes instead of `str`, a list instead of a mapping) raise
`TypeError`. The API is stable from 1.0.0: names, parameters, defaults and error types
change only in a new major version.

Strict mode and the builders check the grammar of RFC 9110 section 11 and these scheme
rules: Basic needs a realm and allows only `charset="UTF-8"`, and its credentials must
decode to `user-id:password`; Bearer needs at least one param, limits the characters of
scope, error, error_description and error_uri, and its credentials are a token68; Digest
quotes and leaves bare the params RFC 7616 lists, needs realm, nonce and qop in challenges
and the response params in credentials, writes `nc` as 8 hex digits, and takes one of
`username` and `username*`. Other schemes get the generic rules only.

## Why

Authentication headers are deceptively hard: one comma separates both the params within a
challenge and the challenges from each other, token68 and auth-params look alike, the
field may be repeated, and each scheme adds quoting rules of its own. What exists on PyPI
covers part of it: `authparser` depends on `pyparsing`, `www-authenticate` had its last
release in 2015, and `wwwauth` parses WWW-Authenticate only. HTTP clients and frameworks
read a challenge only to answer it, and what they write does not always follow RFC 7616:
`requests` and the standard library's urllib quote the Digest `algorithm`, and werkzeug
writes `realm` without quotes. This library parses and builds all five fields, validates
them on request against RFC 9110 and the Basic, Digest and Bearer rules, refuses header
injection when building, and ships typed with no dependencies.

## Testing against the specifications

`python scripts/fetch_upstream.py` downloads the RFCs and the greenbytes WWW-Authenticate
test cases listed in `tests/upstream/MANIFEST.json`, checking each against its sha256.
The suite then reads character sets, quoting lists and examples from them and runs every
test case in both modes; without them those tests skip.

## Documentation

The [GUIDE](https://github.com/JaviLianes8/authchallenge/blob/main/GUIDE.md) describes
every public name, both parsing modes and the rules strict mode checks; the
[CHANGELOG](https://github.com/JaviLianes8/authchallenge/blob/main/CHANGELOG.md) lists
what changed in each release.

## License

MIT. See [LICENSE](https://github.com/JaviLianes8/authchallenge/blob/main/LICENSE).

## Links

- Website: https://lianes8studio.com
- GitHub: https://github.com/JaviLianes8
- LinkedIn: https://www.linkedin.com/in/jlianes/
