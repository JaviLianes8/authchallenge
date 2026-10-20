"""Contracts from the second QA round of 1.0.0: credentials secrecy, iteration, CLI lines."""

from __future__ import annotations

import io
import json
import random
from collections.abc import Iterator
from typing import Any

import pytest

import authchallenge as ac
from authchallenge._cli import main

MARK = "QzX7mark"
TAIL = ', realm="r", nonce="n", uri="/", response="x", cnonce="c", nc=00000001'


@pytest.mark.parametrize(
    "value",
    [
        f"Digest username*=UTF-8''{MARK}%ZZ" + TAIL,
        f"Digest username*=UTF-8'{MARK}-1'abc" + TAIL,
        f"Digest username*={MARK}''abc" + TAIL,
        f"Digest username*=UTF-8''{MARK}%FF%FE" + TAIL,
        f"Digest username*=UTF-8''{MARK}%0A" + TAIL,
        f"Digest username*=UTF-8'{MARK}'abc" + TAIL,
        f"Newauth {MARK}=1, {MARK}=2",
        f'Digest username="u", {MARK}="v", {MARK}="w"',
        f"Basic {MARK}\x01w",
        f"Bearer {MARK}\x7f",
        f'Newauth a="{MARK}\x00"',
        f"Basic {MARK}==",
    ],
)
def test_strict_credentials_errors_quote_no_text_of_them(value: str) -> None:
    with pytest.raises(ac.AuthError) as caught:
        ac.parse_authorization(value, strict=True)
    assert MARK.lower() not in str(caught.value).lower()
    assert "character '" not in str(caught.value)


def test_strict_credentials_errors_do_not_name_a_duplicate_param() -> None:
    with pytest.raises(ac.AuthError) as caught:
        ac.parse_authorization('Digest username="u", username="v"', strict=True)
    assert str(caught.value) == "duplicate auth-param at offset 21"
    with pytest.raises(ac.AuthError, match="duplicate auth-param 'realm' at offset"):
        ac.parse_challenges('Basic realm="a", realm="b"', strict=True)


def test_a_bad_octet_in_credentials_gives_only_its_offset() -> None:
    with pytest.raises(ac.AuthError) as caught:
        ac.parse_authorization("Basic dTp\x01w", strict=True)
    assert str(caught.value) == "a character a field value cannot hold at offset 9"
    with pytest.raises(ac.AuthError, match=r"character '\\x01' is not allowed"):
        ac.parse_challenges('Basic realm="\x01"', strict=True)


def test_strict_credentials_never_quote_a_seeded_secret() -> None:
    rng = random.Random(20261021)
    pieces = [MARK, "=", '"', ",", " ", "\t", "*", "'", "%", "\x01", "\x7f", "\xe9", "\\", "\n"]
    heads = ["Basic ", "Bearer ", "Digest ", "Newauth ", "Digest username*=", ""]
    for _ in range(4_000):
        value = rng.choice(heads) + "".join(rng.choice(pieces) for _ in range(rng.randint(1, 9)))
        try:
            ac.parse_authorization(value, strict=True)
        except ac.AuthError as error:
            assert MARK.lower() not in str(error).lower(), (value, str(error))


@pytest.mark.parametrize(
    "creds",
    [
        ac.Credentials("dXNlcjpwYXNzd29yZA"),
        ac.Credentials("c2VjcmV0OnBhc3N3b3Jk"),
        ac.Credentials("Digest", token68="QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
    ],
)
def test_decode_basic_never_quotes_the_scheme_of_credentials(creds: ac.Credentials) -> None:
    with pytest.raises(ac.AuthError) as caught:
        ac.decode_basic(creds)
    assert str(caught.value) == "not Basic credentials: the scheme is not Basic"


def test_decode_basic_of_a_schemeless_value_parsed_tolerantly_hides_it() -> None:
    with pytest.raises(ac.AuthError) as caught:
        ac.decode_basic(ac.parse_authorization("dXNlcjpwYXNzd29yZA"))
    assert "dXNlcjpw" not in str(caught.value)


def _faulty() -> Iterator[ac.Challenge]:
    yield ac.Challenge("Basic")
    raise TypeError("inner bug")


def test_select_challenge_lets_a_type_error_of_the_iterable_through() -> None:
    with pytest.raises(TypeError, match="inner bug"):
        ac.select_challenge(_faulty(), "basic")


def test_parsers_let_a_type_error_of_the_iterable_through() -> None:
    def lines() -> Iterator[str]:
        yield "Basic realm=a"
        raise TypeError("inner bug")

    with pytest.raises(TypeError, match="inner bug"):
        ac.parse_challenges(lines())
    with pytest.raises(TypeError, match="inner bug"):
        ac.parse_auth_info(lines())


def _cli(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], raw: bytes,
         *argv: str) -> tuple[int, Any]:  # fmt: skip
    stdin = io.TextIOWrapper(io.BytesIO(raw), encoding="latin-1")
    monkeypatch.setattr("sys.stdin", stdin)
    code = main(list(argv))
    return code, json.loads(capsys.readouterr().out)


def test_cli_joins_a_folded_line_that_starts_with_a_tab(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    raw = b'HTTP/1.1 401 X\r\nWWW-Authenticate: Basic\r\n\trealm="x"\r\n'
    code, report = _cli(monkeypatch, capsys, raw)
    assert code == 0
    assert report[0]["challenges"][0]["params"] == {"realm": "x"}


@pytest.mark.parametrize("space", [b"\x0b", b"\x0c", b"\x85"])
def test_cli_first_line_of_other_whitespace_is_a_plain_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], space: bytes
) -> None:
    _, report = _cli(monkeypatch, capsys, space + b'\nWWW-Authenticate: Basic realm="x"\n')
    assert len(report) == 2
    assert report[1]["challenges"][0]["scheme"] == "WWW-Authenticate"


def test_cli_keeps_a_trailing_form_feed_in_a_plain_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, report = _cli(monkeypatch, capsys, b'Basic realm="x"\x0c\n', "--strict")
    assert code == 1
    assert "is not allowed in a field value at offset 15" in report[0]["error"]
