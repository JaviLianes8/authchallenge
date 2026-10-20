"""Digest quoting rules, always run, without the fetched RFC text.

Hand-written: the lists below were copied by hand from RFC 7616 sections 3.3, 3.4 and
3.5 (https://www.rfc-editor.org/rfc/rfc7616.txt). They are not read from the library,
so dropping a name from its own lists makes these tests fail.
"""

from __future__ import annotations

import pytest

import authchallenge as ac

QUOTED = {
    "challenge": ["realm", "domain", "nonce", "opaque", "qop"],
    "credentials": ["username", "realm", "nonce", "uri", "response", "cnonce", "opaque"],
    "info": ["nextnonce", "rspauth", "cnonce"],
}
BARE = {
    "challenge": ["stale", "algorithm"],
    "credentials": ["algorithm", "qop", "nc"],
    "info": ["qop", "nc"],
}
VALUES = {"stale": "false", "algorithm": "SHA-256", "qop": "auth", "nc": "00000001"}
BASE = {
    "challenge": {"realm": "r", "nonce": "n", "qop": "auth"},
    "credentials": {
        "username": "u",
        "realm": "r",
        "nonce": "n",
        "uri": "/",
        "response": "x",
        "cnonce": "c",
        "nc": "00000001",
        "qop": "auth",
    },
    "info": {"rspauth": "a", "cnonce": "c", "nc": "00000001", "qop": "auth"},
}


def _params(kind: str, name: str) -> dict[str, str]:
    params = dict(BASE[kind])
    params[name] = VALUES.get(name, "abc")
    return params


def _build(kind: str, params: dict[str, str]) -> str:
    if kind == "challenge":
        return ac.build_challenge("Digest", params)
    if kind == "credentials":
        return ac.build_authorization("Digest", params)
    return ac.build_auth_info(params, scheme="Digest")


def _parse(kind: str, text: str) -> object:
    if kind == "challenge":
        return ac.parse_challenges(text, strict=True)
    if kind == "credentials":
        return ac.parse_authorization(text, strict=True)
    return ac.parse_auth_info(text, strict=True, scheme="Digest")


def _flip(text: str, name: str, value: str, quoted: bool) -> str:
    written = f'{name}="{value}"' if quoted else f"{name}={value}"
    other = f"{name}={value}" if quoted else f'{name}="{value}"'
    assert written in text, (written, text)
    return text.replace(written, other)


CASES = [(kind, name, True) for kind, names in QUOTED.items() for name in names] + [
    (kind, name, False) for kind, names in BARE.items() for name in names
]


@pytest.mark.parametrize("kind, name, quoted", CASES)
def test_digest_quoting_is_built_and_enforced(kind: str, name: str, quoted: bool) -> None:
    params = _params(kind, name)
    text = _build(kind, params)
    _parse(kind, text)
    with pytest.raises(ac.AuthError, match=r"must be a quoted-string|must not be quoted"):
        _parse(kind, _flip(text, name, params[name], quoted))
