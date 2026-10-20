"""The command line reads stdin as received octets (latin-1) and maps every field name."""

from __future__ import annotations

import gc
import io
import json
import time
from typing import Any

import pytest

import authchallenge as ac
from authchallenge._cli import _fields, main


def _run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], raw: bytes, *argv: str
) -> tuple[int, Any]:
    # A real stdin: text decoding the platform would choose, with the octets underneath.
    stdin = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8", errors="surrogateescape")
    monkeypatch.setattr("sys.stdin", stdin)
    code = main(list(argv))
    return code, json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("octets", [b"caf\xe9", b"\x80\x81", b"caf\xe2\x80\xa8e"])
@pytest.mark.parametrize("strict", [False, True])
def test_obs_text_is_read_as_latin_1(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    octets: bytes,
    strict: bool,
) -> None:
    value = b'Basic realm="' + octets + b'"'
    flags = ["--strict"] if strict else []
    code, report = _run(monkeypatch, capsys, b"WWW-Authenticate: " + value + b"\r\n", *flags)
    expected = ac.parse_challenges(value.decode("latin-1"), strict=strict)
    assert code == 0
    assert report[0]["challenges"][0]["params"] == expected[0].params
    assert report[0]["challenges"][0]["params"]["realm"] == octets.decode("latin-1")


@pytest.mark.parametrize("char", [b"\x0b", b"\x0c", b"\x1c", b"\x1d", b"\x1e", b"\x85"])
def test_only_line_feed_ends_a_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], char: bytes
) -> None:
    _, plain = _run(monkeypatch, capsys, b'Basic realm="a' + char + b'b"\n', "--strict")
    assert len(plain) == 1
    if char != b"\x85":
        assert "is not allowed" in plain[0]["error"]
    dump = b'WWW-Authenticate: Basic realm="a' + char + b'b"\n'
    _, report = _run(monkeypatch, capsys, dump)
    assert len(report) == 1
    assert report[0]["challenges"][0]["params"]["realm"] == "a" + char.decode("latin-1") + "b"


def test_every_field_name_maps_to_its_kind(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    dump = (
        b"HTTP/1.1 407 X\r\n"
        b'WWW-Authenticate: Basic realm="a"\r\n'
        b'Proxy-Authenticate: Basic realm="b"\r\n'
        b"Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n"
        b"Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n"
        b"Authentication-Info: qop=auth\r\n"
        b"Proxy-Authentication-Info: nc=00000001\r\n"
    )
    code, report = _run(monkeypatch, capsys, dump)
    assert code == 0
    kinds = [next(key for key in entry if key != "field") for entry in report]
    assert kinds == ["challenges", "challenges", "credentials", "credentials", "info", "info"]


def _best(lines: int) -> float:
    text = 'WWW-Authenticate: Basic realm="a"\n' + (" " + "y" * 50 + "\n") * lines
    times = []
    gc.disable()
    try:
        for _ in range(3):
            start = time.perf_counter()
            assert len(_fields(text, "WWW-Authenticate")) == 1
            times.append(time.perf_counter() - start)
    finally:
        gc.enable()
    return min(times)


def test_folded_continuation_lines_are_linear() -> None:
    base = max(_best(5_000), 0.001)
    # Eight times the lines: linear code takes about eight times as long, quadratic 64.
    assert _best(40_000) < base * 24
