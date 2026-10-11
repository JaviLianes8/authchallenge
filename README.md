# authchallenge

Parse and build HTTP WWW-Authenticate, Proxy-Authenticate and Authorization headers per RFC 7235, zero dependencies.

## Install

```
pip install authchallenge
```

## Usage

Parse the challenges a server offers:

```python
from authchallenge import parse_challenges

challenges = parse_challenges('Basic realm="simple", Newauth realm="apps", type=1')
# [Challenge(scheme='Basic', token68=None, params={'realm': 'simple'}),
#  Challenge(scheme='Newauth', token68=None, params={'realm': 'apps', 'type': '1'})]
```

A single comma separates both the params inside a challenge and the challenges from one
another; the scheme tokens disambiguate the two. A token68 challenge is parsed as such:

```python
parse_challenges("Negotiate a87421bff012e83c==")
# [Challenge(scheme='Negotiate', token68='a87421bff012e83c==', params={})]
```

Build a challenge. Values are quoted only when they are not a bare token:

```python
from authchallenge import build_challenge

build_challenge("Digest", {"realm": "my zone", "algorithm": "MD5"})
# 'Digest realm="my zone", algorithm=MD5'
```

Parse the credentials a client sends back, as a token68 or as auth-params:

```python
from authchallenge import parse_authorization, build_authorization

parse_authorization("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
# Credentials(scheme='Basic', token68='QWxhZGRpbjpvcGVuIHNlc2FtZQ==', params={})

build_authorization("Digest", {"username": "Mufasa", "uri": "/dir/index.html"})
# 'Digest username="Mufasa", uri="/dir/index.html"'
```

Param names are case-insensitive and returned lower-cased. Parsing is tolerant of
malformed input and returns what it can; building raises `AuthError` on invalid input
(a bad scheme, an invalid token68, or both a token68 and params at once).

## Why

RFC 7235 auth headers are deceptively hard: one comma separates both the params within a
challenge and the challenges from each other, token68 and quoted auth-params look alike,
and the Authorization line mirrors the same grammar. The existing options fall short:
`authparser` pulls in `pyparsing`, `www-authenticate` has been unmaintained since 2015 and
only parses, and the newer `wwwauth` parses WWW-Authenticate alone and requires a very
recent Python. This library parses the challenge list and the Authorization credentials,
builds both back, handles token68, and ships typed with no dependencies.

## License

MIT. See [LICENSE](LICENSE).

## Links

- Website: https://lianes8studio.com
- GitHub: https://github.com/JaviLianes8
- LinkedIn: https://www.linkedin.com/in/jlianes/
