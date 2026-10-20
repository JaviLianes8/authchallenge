"""Contracts from the first QA round of 1.0.0: codecs, wrong types, strict grammar, secrets."""

from __future__ import annotations

import base64
import random
from collections.abc import Callable

import pytest

import authchallenge as ac

CONTROLS = ["\x00", "\n", "\r", "\x1f", "\x7f", "\x80", "\x85", "\x9f"]


@pytest.mark.parametrize("char", CONTROLS)
def test_encode_ext_value_refuses_what_decode_refuses(char: str) -> None:
    with pytest.raises(ac.AuthError, match="control character"):
        ac.encode_ext_value("a" + char + "b")


def test_ext_value_round_trips_every_accepted_text() -> None:
    rng = random.Random(20261020)
    pool = [chr(code) for code in range(0x00, 0x180)] + ["\u20ac", "\u2028", "\U0001f600", "\ud800"]
    for _ in range(5_000):
        text = "".join(rng.choice(pool) for _ in range(rng.randint(0, 8)))
        try:
            encoded = ac.encode_ext_value(text)
        except ac.AuthError:
            continue
        assert ac.decode_ext_value(encoded) == text


@pytest.mark.parametrize(
    "call",
    [
        lambda: ac.select_challenge(None, "basic"),  # type: ignore[arg-type]
        lambda: ac.select_challenge(5, "basic"),  # type: ignore[arg-type]
        lambda: ac.select_challenge([ac.Challenge(1)], "a"),  # type: ignore[arg-type]
        lambda: ac.select_challenge([ac.Challenge(None)], "basic"),  # type: ignore[arg-type]
        lambda: ac.decode_basic(ac.Credentials("Basic", 1)),  # type: ignore[arg-type]
    ],
)
def test_wrong_types_inside_arguments_name_the_argument(call: Callable[[], object]) -> None:
    with pytest.raises(TypeError, match=r"challenges|scheme|token68"):
        call()


@pytest.mark.parametrize("value", ["x=y", "Basic dTpw=, x=y", "Newauth\t, x=1"])
def test_strict_credentials_errors_speak_of_credentials(value: str) -> None:
    with pytest.raises(ac.AuthError) as caught:
        ac.parse_authorization(value, strict=True)
    assert "challenge" not in str(caught.value)


@pytest.mark.parametrize(
    "value", ["Newauth\t, x=1", 'Basic\t, realm="a"', "Newauth\t ,x=1", "Newauth\t\t, x=1"]
)
def test_strict_challenge_needs_a_space_not_a_tab_after_the_scheme(value: str) -> None:
    with pytest.raises(ac.AuthError, match="outside a challenge"):
        ac.parse_challenges(value, strict=True)
    assert ac.parse_challenges(value)[0].params  # tolerant mode still reads the params


def test_space_then_tab_before_the_comma_is_valid() -> None:
    found = ac.parse_challenges("Newauth \t, x=1", strict=True)
    assert found == [ac.Challenge("Newauth", params={"x": "1"})]


BAD_LANGUAGES = [
    "1",
    "-",
    "en--US",
    "abcdefghijk",
    "en-",
    "x",
    "en-a",
    "en-a-b",
    "i-foo",
    "zh-abc-def-ghi-jkl",
]
GOOD_LANGUAGES = [
    "",
    "en",
    "EN-us",
    "zh-Hant-TW",
    "de-CH-1996",
    "sl-rozaj-biske",
    "zh-yue-HK",
    "es-419",
    "en-a-bbb-x-a-ccc",
    "x-whatever",
    "i-klingon",
    "zh-min-nan",
    "en-GB-oed",
    "zh-abc-def",
    "zh-abc-def-ghi",
    "abcd",
]


@pytest.mark.parametrize("language", BAD_LANGUAGES)
def test_ext_value_language_must_be_a_language_tag(language: str) -> None:
    with pytest.raises(ac.AuthError):
        ac.decode_ext_value(f"UTF-8'{language}'abc")


@pytest.mark.parametrize("language", GOOD_LANGUAGES)
def test_ext_value_language_tags_of_rfc_5646_are_read(language: str) -> None:
    assert ac.decode_ext_value(f"UTF-8'{language}'abc") == "abc"


def test_strict_digest_refuses_a_username_star_with_a_bad_language() -> None:
    value = (
        'Digest username*=UTF-8\'1\'x, realm="a", nonce="n", uri="/", '
        'response="r", cnonce="c", nc=00000001, qop=auth'
    )
    with pytest.raises(ac.AuthError):
        ac.parse_authorization(value, strict=True)


def test_basic_errors_chain_nothing_that_holds_the_credentials() -> None:
    latin = base64.b64encode("alice:pässw0rd".encode("latin-1")).decode()
    calls: list[Callable[[], object]] = [
        lambda: ac.encode_basic("alice", "S3cr€T-pass", charset="latin-1"),
        lambda: ac.decode_basic("Basic " + latin),
        lambda: ac.decode_basic("Basic c2Vj-mV0"),
        lambda: ac.parse_authorization("Basic c2Vj-mV0", strict=True),
    ]
    for call in calls:
        with pytest.raises(ac.AuthError) as caught:
            call()
        # A traceback prints the whole chain: only our own messages may be in it.
        error: BaseException | None = caught.value
        while error is not None:
            assert isinstance(error, ac.AuthError), repr(error)
            assert not any(part in str(error) for part in ("S3cr", "w0rd", "c2Vj"))
            error = error.__cause__ or error.__context__


@pytest.mark.parametrize("charset", ["utf\x00-8", "latin\x00"])
def test_a_charset_with_nul_is_an_auth_error(charset: str) -> None:
    with pytest.raises(ac.AuthError):
        ac.encode_basic("a", "b", charset=charset)
    with pytest.raises(ac.AuthError):
        ac.decode_basic("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", charset=charset)


@pytest.mark.parametrize(
    "call, secret",
    [
        (lambda: ac.decode_basic("Basic\x0bQWxhZGRpbjpvcGVuIHNlc2FtZQ== x"), "QWxhZGRp"),
        (lambda: ac.decode_basic("QWxhZGRpbjpvcGVu x"), "QWxhZGRp"),
        (lambda: ac.parse_authorization("Bearer mF_9.B5f-4.1JqM=x/y", strict=True), "mf_9"),
        (
            lambda: ac.parse_authorization("Basic dXNlcjpwYXNzd29yZA=x/", strict=True),
            "dxnlcjp",
        ),
        (lambda: ac.parse_authorization("Basic dTpw=, dTpw=x", strict=True), "dtpw"),
    ],
)
def test_credentials_errors_never_repeat_credential_material(
    call: Callable[[], object], secret: str
) -> None:
    with pytest.raises(ac.AuthError) as caught:
        call()
    assert secret.lower() not in str(caught.value).lower()
