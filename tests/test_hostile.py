"""Hostile input: every shape stays linear, every error stays small and typed."""

from __future__ import annotations

import io
import sys
import time
from collections.abc import Callable

import pytest

import authchallenge as ac
from authchallenge._cli import main

SHAPES: dict[str, Callable[[int], str]] = {
    "commas": lambda n: "," * n,
    "comma space": lambda n: ", " * n,
    "equals": lambda n: "a" + "=" * n,
    "params": lambda n: "X " + "a=b, " * (n // 5),
    "challenges": lambda n: "X, " * (n // 3),
    "quotes": lambda n: '"' * n,
    "escapes": lambda n: 'X a="' + "\\" * n + '"',
    "escaped quotes": lambda n: 'X a="' + '\\"' * (n // 2),
    "open quote": lambda n: 'X a="' + "b, c=d " * (n // 7),
    "token68": lambda n: "X " + "a" * n + "==",
    "padding": lambda n: "X a" + "=" * n + " b",
    "folds": lambda n: "X a=b" + "\r\n " * (n // 3),
    "line breaks": lambda n: "X a=b\n" * (n // 6),
    "spaces then junk": lambda n: "X" + " " * n + "!",
    "tabs and spaces": lambda n: "X a" + " \t" * (n // 2) + "=b",
    "scheme run": lambda n: "a " * (n // 2),
    "high octets": lambda n: 'X a="' + "\xe9" * n + '"',
}


def _best(call: Callable[[], object]) -> float:
    times = []
    for _ in range(3):
        start = time.perf_counter()
        try:
            call()
        except ac.AuthError as error:
            assert len(str(error)) < 300
        times.append(time.perf_counter() - start)
    return min(times)


def _calls(text: str) -> list[Callable[[], object]]:
    return [
        lambda: ac.parse_challenges(text),
        lambda: ac.parse_challenges(text, strict=True),
        lambda: ac.parse_authorization(text),
        lambda: ac.parse_authorization(text, strict=True),
        lambda: ac.parse_auth_info(text, strict=True, scheme="Digest"),
        lambda: ac.parse_auth_info(text),
    ]


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_every_shape_is_linear(shape: str) -> None:
    small, large = SHAPES[shape](25_000), SHAPES[shape](100_000)
    for quick, slow in zip(_calls(small), _calls(large), strict=True):
        base = max(_best(quick), 0.002)
        # Four times the input: linear code takes about four times as long, quadratic 16.
        assert _best(slow) < base * 10, shape


def test_many_field_lines_are_linear() -> None:
    lines = ['Basic realm="a"'] * 50_000
    start = time.perf_counter()
    assert len(ac.parse_challenges(lines, strict=True)) == 50_000
    assert time.perf_counter() - start < 20


def test_codecs_on_megabyte_input() -> None:
    big = "QUFB" * 250_000
    start = time.perf_counter()
    with pytest.raises(ac.AuthError, match="lack the ':'"):
        ac.decode_basic("Basic " + big)
    assert ac.decode_ext_value("UTF-8''" + "%41" * 300_000) == "A" * 300_000
    assert ac.encode_ext_value("é" * 300_000).count("%") == 600_000
    with pytest.raises(ac.AuthError) as caught:
        ac.decode_ext_value("UTF-8''" + "%4" * 300_000)
    assert len(str(caught.value)) < 100
    assert time.perf_counter() - start < 20


def test_the_command_line_reads_a_large_dump(monkeypatch: pytest.MonkeyPatch) -> None:
    dump = "HTTP/1.1 401\r\n" + "X-Junk: a\r\n" * 20_000 + 'WWW-Authenticate: Basic realm="a"\r\n'
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO(dump))
    monkeypatch.setattr(sys, "stdout", out)
    start = time.perf_counter()
    assert main([]) == 0
    assert time.perf_counter() - start < 20
    assert '"realm": "a"' in out.getvalue()


def test_deep_recursion_limit_is_not_needed() -> None:
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(100)
    try:
        text = 'X a="' + "(" * 50_000 + '"'
        assert ac.parse_challenges(text, strict=True)[0].params["a"] == "(" * 50_000
    finally:
        sys.setrecursionlimit(limit)
