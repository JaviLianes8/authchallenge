# authchallenge guide

The behaviour of every public name in detail. Each Python block below runs as a test:
the comment lines at the end of a block hold what it prints, in order.

## The five fields

| Field | Parse | Build |
| --- | --- | --- |
| `WWW-Authenticate`, `Proxy-Authenticate` | `parse_challenges` | `build_challenge`, `build_bearer_challenge` |
| `Authorization`, `Proxy-Authorization` | `parse_authorization` | `build_authorization`, `encode_basic` |
| `Authentication-Info`, `Proxy-Authentication-Info` | `parse_auth_info` | `build_auth_info` |

Field values are `str`. Bytes received from a socket are decoded as latin-1 first, which
maps every octet to one character, so nothing is lost. Passing `bytes` raises `TypeError`.

## Two ways to read a header

**Default: tolerant.** Malformed list elements are skipped and the rest is kept, as user
agents do:

- obsolete line folding (a line break followed by spaces) reads as one space;
- a bare line break ends a field line, so the next line keeps its challenges;
- of two params with the same name (compared without case) the first wins;
- a param that cannot belong to a challenge, or junk after a value, is dropped;
- a challenge with a token68 never collects params that follow it.

**`strict=True`: exactly the RFCs.** The grammar of RFC 9110 section 11 and the rules of
Basic, Digest and Bearer. The first broken rule raises `AuthError`; the message names the
rule and, for grammar errors, the offset in the field value (and the field line when
several were given).

```python
from authchallenge import AuthError, parse_challenges

header = 'Basic realm="a", realm="b", Newauth\r\n x=1'
print(parse_challenges(header))
try:
    parse_challenges(header, strict=True)
except AuthError as error:
    print(error)
# [Challenge(scheme='Basic', token68=None, params={'realm': 'a'}), Challenge(scheme='Newauth', token68=None, params={'x': '1'})]
# obsolete line folding at offset 35
```

What strict mode checks:

- the field holds characters a field value can hold (tab, space, visible ASCII and
  0x80 to 0xFF), no obsolete line folding, no unterminated quoted-string;
- a challenge is a scheme, then one or more spaces (not tabs), then a token68 or a
  comma-separated list of params; empty list elements are allowed, as RFC 9110 section
  5.6.1 asks recipients to accept;
- param names are unique within a challenge; `realm` is a quoted-string in a challenge;
- credentials are one scheme with its token68 or params: nothing may follow a token68,
  and only a space may follow the scheme;
- Basic: a realm, `charset` only `UTF-8`, credentials that decode to `user-id:password`;
- Bearer: at least one param in a challenge, the character sets of RFC 6750 for scope,
  error, error_description and error_uri, a token68 as credentials;
- Digest: the params RFC 7616 lists as quoted are quoted and the ones it lists as bare
  are bare, realm, nonce and qop in a challenge, the response params in credentials,
  `nc` as 8 hex digits, `stale` and `userhash` as true or false, exactly one of
  `username` and `username*`, and rspauth, cnonce and nc in Authentication-Info with qop.

Other schemes get the grammar rules only.

## Results

`Challenge` and `Credentials` are frozen dataclasses with `scheme`, `token68` and
`params`. The scheme keeps its case; param names are lower-cased and values unquoted.
They compare by value and pickle; they are not hashable, since `params` is a dict.
`repr` of `Credentials` hides the token68, which is a password or a bearer token.

```python
from authchallenge import parse_authorization, parse_challenges

creds = parse_authorization("Bearer mF_9.B5f-4.1JqM")
print(creds)
print(creds.token68)
print(parse_authorization(", ="))
print(parse_challenges('NEWAUTH Realm="Apps"')[0].params)
# Credentials(scheme='Bearer', token68=<hidden>, params={})
# mF_9.B5f-4.1JqM
# Credentials(scheme='', token68=None, params={})
# {'realm': 'Apps'}
```

Tolerant `parse_authorization` returns the first credentials, or `Credentials("")` when
the value holds none.

## Building

`build_challenge`, `build_authorization` and `build_auth_info` quote what the sender
rules say to quote and refuse what strict parsing would refuse, so their output always
reads back with `strict=True` to the same values. Values may hold only tab, space and
visible ASCII: a CR or LF can never split the header. Other text goes in an RFC 8187
ext-value under a `name*` param.

```python
from authchallenge import (
    AuthError,
    build_authorization,
    build_challenge,
    encode_ext_value,
)

print(build_challenge("Newauth", {"realm": "apps", "type": "1", "title": "Login Page"}))
user = encode_ext_value("Jäsøn Doe")
fields = {"username*": user, "realm": "api", "nonce": "n1", "uri": "/", "response": "8ca5"}
print(build_authorization("Digest", {**fields, "cnonce": "c1", "nc": "00000001", "qop": "auth"}))
for scheme, params in (("Basic", {}), ("Digest", {"realm": "a", "nc": "1"})):
    try:
        build_challenge(scheme, params)
    except AuthError as error:
        print(error)
# Newauth realm="apps", type=1, title="Login Page"
# Digest username*=UTF-8''J%C3%A4s%C3%B8n%20Doe, realm="api", nonce="n1", uri="/", response="8ca5", cnonce="c1", nc=00000001, qop=auth
# Basic needs the 'realm' parameter
# the Digest nc parameter is exactly 8 hexadecimal digits
```

`build_bearer_challenge` takes the RFC 6750 attributes as keywords; `scope` may be a
string or an iterable of scope tokens. `build_auth_info` takes the `scheme` of the
request's credentials to apply its rules.

## Basic and ext-values

`encode_basic` and `decode_basic` implement RFC 7617: the user-id has no colon, neither
part has a control character, and the charset is UTF-8 (the default, what a server asks
for with `charset="UTF-8"`) or latin-1. `decode_basic` takes the field value or parsed
`Credentials`; the password is everything after the first colon.

`encode_ext_value` writes `UTF-8''` and percent-encoded UTF-8, and refuses text with
control characters (C0, DEL, C1), so whatever it writes reads back. `decode_ext_value`
reads UTF-8 and ISO-8859-1 ext-values, checks that the language, when given, is an RFC
5646 language tag, and refuses text that decodes to control characters.

```python
from authchallenge import AuthError, decode_basic, decode_ext_value, encode_basic

print(encode_basic("Aladdin", "open sesame"))
print(decode_basic("Basic dXNlcjpwYTpzcw=="))
print(decode_ext_value("utf-8'en'%C2%A3%20rates"))
for call in (lambda: decode_basic("Basic dXNlcg=="), lambda: decode_ext_value("UTF-8''%0A")):
    try:
        call()
    except AuthError as error:
        print(error)
# Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
# ('user', 'pa:ss')
# £ rates
# Basic credentials lack the ':' between user-id and password
# ext-value decodes to control characters
```

## Choosing a challenge

`select_challenge(challenges, *schemes)` returns the first challenge of the first scheme
in your list that the server offered, comparing schemes without case, or `None`.

## Errors

`AuthError` is a `ValueError`. Its message quotes at most 40 characters of the input,
never a token68 and no other text of credentials, and it chains no exception that holds
the input. Arguments of the wrong type raise `TypeError` naming the argument.

```python
from authchallenge import AuthError, build_challenge, decode_basic

for call in (lambda: decode_basic("Basic c2VjcmV0!"), lambda: build_challenge("X", [])):
    try:
        call()
    except (AuthError, TypeError) as error:
        print(type(error).__name__, error)
# AuthError invalid token68: Basic credentials are base64 after the scheme
# TypeError params must be a mapping, not list
```

## Command line

`authchallenge` (or `python -m authchallenge`) prints the parsed fields as JSON. Values
come as arguments, one per stdin line, or as a header dump on stdin such as `curl -sI`
output, of which only the authentication fields are read; the first non-empty line
decides which. `--authorization` and `--info` read the values as credentials or
Authentication-Info. `--strict` reports the first broken rule of each value on stderr
and exits 1. Stdin is read as octets decoded as latin-1, like any received field value,
and only LF (with an optional CR before it) ends a line.
