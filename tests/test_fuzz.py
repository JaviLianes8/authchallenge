"""Seeded property tests: hostile input never escapes as another error, and strict mode
accepts exactly what an independent recognizer of the RFC 9110 grammar accepts.

The recognizer below is written by hand from the ABNF of RFC 9110 sections 5.6.1
(lists, with the empty elements recipients must accept), 5.6.2 (token), 5.6.4
(quoted-string) and 11 (challenge, credentials, token68, auth-param); it shares no code
with the library.
"""

from __future__ import annotations

import contextlib
import random
import re

import pytest

import authchallenge as ac

SEEDS = [1, 20261019, 987654321]

TOKEN = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
TOKEN68 = r"[A-Za-z0-9\-._~+/]+=*"
QUOTED = r'"(?:[\t \x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t \x21-\x7e\x80-\xff])*"'
OWS = r"[ \t]*"
PARAM = rf"{TOKEN}{OWS}={OWS}(?:{TOKEN}|{QUOTED})"
PARAMS = rf"(?:{PARAM})?(?:{OWS},{OWS}(?:{PARAM})?)*"
CHALLENGE = rf"{TOKEN}(?: +(?:{TOKEN68}|{PARAMS}))?"
CHALLENGES = re.compile(rf"{OWS}(?:,{OWS})*{CHALLENGE}(?:{OWS},(?:{OWS}{CHALLENGE})?)*{OWS}")
CREDENTIALS = re.compile(rf"{OWS}{TOKEN}(?: +(?:{TOKEN68}|{PARAMS}))?{OWS}")
INFO = re.compile(rf"{OWS}{PARAMS}{OWS}")

PIECES = [
    " ", "  ", "\t", ",", ", ", " ,", "=", " = ", "==", "abc==", "a/b+", "x.y~z",
    '"v w"', '"a\\"b"', '"\\\\"', '""', '"bad', '"é"', "é", "\x00", "\r\n", "\r\n ", ";",
    "\\", '"', "€",
]  # fmt: skip


def _hostile(rng: random.Random, counter: list[int]) -> str:
    """Random text over the field grammar's pieces; every token is new, so names never repeat."""
    parts: list[str] = []
    for _ in range(rng.randint(1, 9)):
        if rng.random() < 0.4:
            counter[0] += 1
            parts.append(f"t{counter[0]}")
        else:
            parts.append(rng.choice(PIECES))
    return "".join(parts)


def _outcome(call: object) -> tuple[bool, str]:
    assert callable(call)
    try:
        call()
    except ac.AuthError as error:
        message = str(error)
        assert len(message) < 300, message
        return False, message
    return True, ""


@pytest.mark.parametrize("seed", SEEDS)
def test_strict_challenges_accept_exactly_the_grammar(seed: int) -> None:
    rng, counter = random.Random(seed), [0]
    for _ in range(6000):
        text = _hostile(rng, counter)
        accepted, why = _outcome(lambda t=text: ac.parse_challenges(t, strict=True))
        assert accepted == (CHALLENGES.fullmatch(text) is not None), (text, why)


@pytest.mark.parametrize("seed", SEEDS)
def test_strict_credentials_and_info_accept_exactly_the_grammar(seed: int) -> None:
    rng, counter = random.Random(seed), [0]
    for _ in range(6000):
        text = _hostile(rng, counter)
        accepted, why = _outcome(lambda t=text: ac.parse_authorization(t, strict=True))
        assert accepted == (CREDENTIALS.fullmatch(text) is not None), (text, why)
        accepted, why = _outcome(lambda t=text: ac.parse_auth_info(t, strict=True))
        assert accepted == (INFO.fullmatch(text) is not None), (text, why)


@pytest.mark.parametrize("seed", SEEDS)
def test_tolerant_mode_never_raises_and_agrees_with_strict(seed: int) -> None:
    rng, counter = random.Random(seed), [0]
    for _ in range(6000):
        text = _hostile(rng, counter) + rng.choice(["", "\ud800", "\x7f", "\n", "Basic"])
        tolerant = ac.parse_challenges(text)
        assert all(isinstance(c, ac.Challenge) for c in tolerant)
        info = ac.parse_auth_info([text, text])
        creds = ac.parse_authorization(text)
        with contextlib.suppress(ac.AuthError):
            assert ac.parse_challenges(text, strict=True) == tolerant
        with contextlib.suppress(ac.AuthError):
            assert ac.parse_authorization(text, strict=True) == creds
        with contextlib.suppress(ac.AuthError):
            assert ac.parse_auth_info(text, strict=True) == info


def _value(rng: random.Random) -> str:
    alphabet = 'ab Z09"\\,;=\t!~/+.'
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))


@pytest.mark.parametrize("seed", SEEDS)
def test_built_headers_read_back_strictly_to_the_same_values(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(3000):
        scheme = rng.choice(["Newauth", "X-Custom", "a.b"])
        params = {f"p{i}": _value(rng) for i in range(rng.randint(0, 4))}
        if rng.random() < 0.5:
            params["realm"] = _value(rng)
        challenge = ac.build_challenge(scheme, params)
        (read,) = ac.parse_challenges(challenge, strict=True)
        assert (read.scheme, read.params) == (scheme, params)
        creds = ac.build_authorization(scheme, params)
        assert ac.parse_authorization(creds, strict=True) == ac.Credentials(scheme, None, params)
        if params:
            info = ac.build_auth_info(params)
            assert ac.parse_auth_info(info, strict=True) == params


@pytest.mark.parametrize("seed", SEEDS)
def test_codecs_round_trip(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(3000):
        text = "".join(chr(rng.choice([rng.randint(32, 126), rng.randint(160, 0x10FFFF)]))
                       for _ in range(rng.randint(0, 12)))  # fmt: skip
        if any(0xD800 <= ord(c) <= 0xDFFF for c in text):
            continue
        assert ac.decode_ext_value(ac.encode_ext_value(text)) == text
        user = text.replace(":", "")
        header = ac.encode_basic(user, text)
        assert ac.decode_basic(header) == (user, text)
        assert ac.decode_basic(ac.parse_authorization(header, strict=True)) == (user, text)


@pytest.mark.parametrize("seed", SEEDS)
def test_codecs_refuse_garbage_with_auth_error_only(seed: int) -> None:
    rng = random.Random(seed)
    alphabet = "QWxhZGRp=:%'-_ \tBasicUTF8\x00é"
    for _ in range(5000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 20)))
        for call in (
            lambda t=text: ac.decode_basic(t),
            lambda t=text: ac.decode_basic("Basic " + t, charset="latin-1"),
            lambda t=text: ac.decode_ext_value(t),
            lambda t=text: ac.decode_ext_value("UTF-8''" + t),
        ):
            _outcome(call)
