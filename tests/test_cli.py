from __future__ import annotations

import io
import json
from collections.abc import Callable
from typing import Any

import pytest

from authchallenge._cli import main

Result = tuple[int, Any, str]


@pytest.fixture
def run(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> Callable[..., Result]:
    def invoke(argv: list[str], stdin: str = "") -> Result:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
        code = main(argv)
        out, err = capsys.readouterr()
        return code, json.loads(out) if out else None, err

    return invoke


def test_arguments_are_challenge_values(run: Callable[..., Result]) -> None:
    code, report, err = run(['Basic realm="a", Negotiate abc==', "Newauth"])
    assert code == 0 and err == ""
    assert [entry["field"] for entry in report] == ["WWW-Authenticate"] * 2
    first = report[0]["challenges"]
    assert first[0] == {"scheme": "Basic", "token68": None, "params": {"realm": "a"}}
    assert first[1]["token68"] == "abc=="


def test_authorization_and_info_flags(run: Callable[..., Result]) -> None:
    _, report, _ = run(["--authorization", "Basic dTpw"])
    assert report[0]["credentials"]["token68"] == "dTpw"
    _, report, _ = run(["--info", "qop=auth, nc=00000001"])
    assert report[0]["info"] == {"qop": "auth", "nc": "00000001"}


def test_reads_only_auth_fields_from_a_header_dump(run: Callable[..., Result]) -> None:
    dump = (
        "HTTP/1.1 401 Unauthorized\r\ncontent-type: text/html\r\n"
        'www-authenticate: Basic realm="a",\r\n Bearer realm="b"\r\n'
        "Proxy-Authenticate: Negotiate\r\nAuthorization: Bearer t0k\r\n"
        "Authentication-Info: qop=auth\r\nX-Other: Basic\r\n\r\n"
    )
    code, report, _ = run([], dump)
    assert code == 0
    fields = [entry["field"] for entry in report]
    assert fields == [
        "www-authenticate",
        "Proxy-Authenticate",
        "Authorization",
        "Authentication-Info",
    ]
    assert [c["scheme"] for c in report[0]["challenges"]] == ["Basic", "Bearer"]
    assert report[2]["credentials"]["token68"] == "t0k"


def test_plain_stdin_lines_are_each_a_value(run: Callable[..., Result]) -> None:
    code, report, _ = run([], 'Basic realm="a"\n\n Negotiate \n')
    assert code == 0
    assert [entry["challenges"][0]["scheme"] for entry in report] == ["Basic", "Negotiate"]


def test_strict_reports_the_rule_and_exits_one(run: Callable[..., Result]) -> None:
    code, report, err = run(["--strict", "Basic realm=a", 'Basic realm="a"'])
    assert code == 1
    assert "quoted-string" in report[0]["error"] and "challenges" in report[1]
    assert "authchallenge: strict: WWW-Authenticate:" in err


def test_strict_flags_a_folded_dump(run: Callable[..., Result]) -> None:
    code, report, _ = run(["--strict"], 'WWW-Authenticate: Basic\r\n realm="a"\r\n')
    assert code == 1 and "obsolete line folding" in report[0]["error"]


def test_no_input_is_a_usage_error(run: Callable[..., Result]) -> None:
    with pytest.raises(SystemExit) as caught:
        run([], "\n\n")
    assert caught.value.code == 2
