"""Regression tests for the independent review: performance, charsets, CLI mode, offsets."""

from __future__ import annotations

import io
import random
import time

import pytest

from authchallenge import (
    AuthError,
    build_auth_info,
    build_authorization,
    build_challenge,
    decode_basic,
    decode_ext_value,
    encode_basic,
    parse_auth_info,
    parse_authorization,
    parse_challenges,
)
from authchallenge._cli import main

LIMIT = 10.0  # seconds; the quadratic versions took 30 s and more on these inputs


def _timed(call: object) -> float:
    assert callable(call)
    start = time.perf_counter()
    call()
    return time.perf_counter() - start


@pytest.mark.parametrize("strict", [False, True])
def test_long_runs_of_whitespace_are_linear(strict: bool) -> None:
    padded = 'Basic realm="x"' + " " * 200_000
    assert _timed(lambda: parse_challenges(padded, strict=strict)) < LIMIT
    tabs = "X a" + " \t" * 100_000 + "=b"
    assert _timed(lambda: parse_challenges(tabs)) < LIMIT


def test_many_params_are_linear() -> None:
    names = [f"p{i}" for i in range(40_000)]
    text = "X " + ", ".join(f"{name}=v" for name in names)
    assert _timed(lambda: parse_challenges(text, strict=True)) < LIMIT
    assert _timed(lambda: parse_auth_info(text[2:], strict=True)) < LIMIT
    assert _timed(lambda: build_challenge("X", dict.fromkeys(names, "v"))) < LIMIT


@pytest.mark.parametrize("charset", ["utf-16", "utf-32", "nope", "cp037"])
def test_basic_refuses_charsets_that_are_not_ascii_compatible(charset: str) -> None:
    with pytest.raises(AuthError, match="unsupported Basic charset"):
        encode_basic("a", "b", charset=charset)
    with pytest.raises(AuthError, match="unsupported Basic charset"):
        decode_basic("Basic YTpi", charset=charset)


def test_basic_accepts_charset_aliases() -> None:
    for charset in ("UTF8", "iso-8859-1", "latin1"):
        assert decode_basic(encode_basic("a", "b", charset=charset), charset=charset) == ("a", "b")


def test_cli_plain_values_are_kept_when_a_later_line_has_a_colon(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO('Basic realm="a"\nX-Foo: bar\n'))
    assert main([]) == 0
    assert '"realm": "a"' in capsys.readouterr().out


def test_a_bare_newline_ends_a_field_line_in_tolerant_mode() -> None:
    challenges = parse_challenges('Basic realm="a"\nBearer realm="b"\r\nx="c"')
    assert [(c.scheme, c.params) for c in challenges] == [
        ("Basic", {"realm": "a"}),
        ("Bearer", {"realm": "b"}),
    ]
    assert parse_auth_info("a=1\nb=2") == {"a": "1", "b": "2"}


def test_a_token_cut_by_a_stray_character_is_dropped() -> None:
    assert parse_challenges("Newauth realm=caf\xe9, x=1")[0].params == {"x": "1"}
    assert parse_challenges('Newauth a="q"x, b=c d')[0].params == {"a": "q", "b": "c"}


def test_offsets_point_at_the_junk_and_name_the_line() -> None:
    with pytest.raises(AuthError, match=r"at offset 17$"):
        parse_challenges('Basic realm="x"  extra', strict=True)
    with pytest.raises(AuthError, match=r"at offset 0 \(field line 2\)"):
        parse_challenges(['Basic realm="a"', "Basic realm=b"], strict=True)
    with pytest.raises(AuthError, match=r"duplicate .* \(field line 2\)"):
        parse_auth_info(["a=1", "A=2"], strict=True)


@pytest.mark.parametrize("encoded", ["UTF-8''%0D%0A", "UTF-8''a%00", "UTF-8''%7F", "UTF-8''%C2%85"])
def test_ext_values_that_decode_to_controls_are_refused(encoded: str) -> None:
    with pytest.raises(AuthError, match="control characters"):
        decode_ext_value(encoded)
    creds = 'Digest username*=%s, realm="r", nonce="n", uri="/", response="x", cnonce="c", nc=1'
    with pytest.raises(AuthError):
        parse_authorization(creds % encoded, strict=True)


def test_realm_quoting_is_required_of_challenges_only() -> None:
    assert parse_authorization("Newauth realm=r", strict=True).params == {"realm": "r"}
    assert parse_auth_info("realm=r", strict=True) == {"realm": "r"}
    with pytest.raises(AuthError, match="realm"):
        parse_challenges("Newauth realm=r", strict=True)


ALPHABET = [
    "a",
    "Z",
    "0",
    " ",
    "\t",
    '"',
    "\\",
    ",",
    "=",
    ";",
    "'",
    "~",
    "\r",
    "\n",
    "\x00",
    "\xe9",
]


def _text(rng: random.Random) -> str:
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 6)))


def test_built_output_always_passes_strict_parsing() -> None:
    rng = random.Random(20261013)
    built = 0
    for _ in range(20_000):
        scheme = rng.choice(["Newauth", "Basic", "Bearer", "Digest", "x y", ""])
        params = {_text(rng) or "n": _text(rng) for _ in range(rng.randint(0, 3))}
        token68 = rng.choice([None, None, "abc=", _text(rng)])
        for build, parse, kind in (
            (build_challenge, parse_challenges, "challenge"),
            (build_authorization, parse_authorization, "credentials"),
        ):
            try:
                header = build(scheme, params or None, token68)
            except AuthError:
                continue
            built += 1
            assert not set(header) & {"\r", "\n", "\x00"}, header
            parsed = parse(header, strict=True)
            found = parsed[0] if isinstance(parsed, list) else parsed
            assert (found.scheme, found.token68, found.params) == (
                scheme,
                token68,
                {k.lower(): v for k, v in params.items()} if token68 is None else {},
            ), (kind, header)
        try:
            info = build_auth_info(params or {"n": "v"})
        except AuthError:
            continue
        assert parse_auth_info(info, strict=True) == {
            k.lower(): v for k, v in (params or {"n": "v"}).items()
        }
    assert built > 1_000
