"""The PyPI release 0.2.0 as an oracle: 1.0.0 answers the same, except where documented.

Set AUTHCHALLENGE_V02 to a folder holding the 0.2.0 package (for example the unpacked
wheel: `pip download authchallenge==0.2.0 --no-deps` and unzip it); the test skips
otherwise. Results are compared by value and errors by family (AuthError or not).
"""

from __future__ import annotations

import importlib.util
import os
import random
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from test_fuzz import PIECES

import authchallenge as ac


@pytest.fixture(scope="module")
def old() -> ModuleType:
    folder = os.environ.get("AUTHCHALLENGE_V02")
    if not folder:
        pytest.skip("set AUTHCHALLENGE_V02 to the unpacked 0.2.0 release")
    init = Path(folder) / "authchallenge" / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        "authchallenge_v02", init, submodule_search_locations=[str(init.parent)]
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["authchallenge_v02"] = module
    spec.loader.exec_module(module)
    assert module.__version__ == "0.2.0"
    return module


def _plain(result: Any) -> Any:
    if isinstance(result, list):
        return [_plain(item) for item in result]
    if hasattr(result, "scheme"):
        return (result.scheme, result.token68, result.params)
    return result


def _outcome(module: ModuleType, name: str, *args: Any, **kwargs: Any) -> Any:
    try:
        return _plain(getattr(module, name)(*args, **kwargs))
    except ValueError as error:
        return ("error", type(error).__name__ == "AuthError")


def _text(rng: random.Random) -> str:
    words = ["Basic", "Digest", "Bearer", "realm", "nc", "qop", "x", "t1", "QQ==", "dTpw"]
    return "".join(rng.choice(PIECES + words) for _ in range(rng.randint(1, 10)))


def _no_space_after_scheme(text: str) -> bool:
    """The documented change of strict credentials: only a space may follow the scheme."""
    head = text.strip(" \t")
    match = re.match(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", head)
    return match is not None and head[match.end() : match.end() + 1] not in ("", " ")


def _padding_fix(before: Any, after: Any, text: str) -> bool:
    """The documented Basic fix: surplus padding that CPython before 3.13 decoded."""
    token = text.strip(" 	").split(" ")[-1]
    padding = len(token) - len(token.rstrip("="))
    surplus = len(token) % 4 != 0 or padding > 2
    accepted = before is not None and before not in (("error", True), ("error", False))
    lenient = sys.version_info < (3, 13) and accepted
    return lenient and surplus and after == ("error", True)


@pytest.mark.parametrize("seed", [7, 8])
def test_parsers_answer_as_0_2_0(old: ModuleType, seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(20_000):
        text = _text(rng)
        for strict in (False, True):
            for name in ("parse_challenges", "parse_auth_info"):
                assert _outcome(old, name, text, strict=strict) == _outcome(
                    ac, name, text, strict=strict
                ), (name, text, strict)
            before = _outcome(old, "parse_authorization", text, strict=strict)
            after = _outcome(ac, "parse_authorization", text, strict=strict)
            if strict and _no_space_after_scheme(text) and before != after:
                assert after == ("error", True), text
            elif not _padding_fix(before, after, text):
                assert before == after, text


@pytest.mark.parametrize("seed", [9])
def test_builders_and_codecs_answer_as_0_2_0(old: ModuleType, seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(10_000):
        scheme = rng.choice(["Basic", "Bearer", "Digest", "Newauth", "a b", ""])
        params = {rng.choice(["realm", "nc", "qop", "nonce", "x", "X"]): _text(rng)[:6]}
        token = rng.choice([None, "abc==", "QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "a b"])
        for name in ("build_challenge", "build_authorization"):
            assert _outcome(old, name, scheme, params) == _outcome(ac, name, scheme, params)
            assert _outcome(old, name, scheme, None, token) == _outcome(
                ac, name, scheme, None, token
            )
        assert _outcome(old, "build_auth_info", params, scheme=scheme or None) == _outcome(
            ac, "build_auth_info", params, scheme=scheme or None
        )
        text = _text(rng)
        for name, args in (
            ("decode_basic", ("Basic " + text,)),
            ("decode_basic", (text,)),
            ("decode_ext_value", (text,)),
            ("encode_ext_value", (text,)),
            ("encode_basic", (text.replace(":", ""), text)),
        ):
            before, after = _outcome(old, name, *args), _outcome(ac, name, *args)
            if not (name == "decode_basic" and _padding_fix(before, after, args[0])):
                assert before == after, (name, args)


def test_documented_changes_against_0_2_0(old: ModuleType) -> None:
    with pytest.raises(old.AuthError):
        old.build_challenge("X", {"a": 1})
    with pytest.raises(TypeError):
        ac.build_challenge("X", {"a": 1})  # type: ignore[dict-item]
    assert old.parse_authorization("Foo,", strict=True).scheme == "Foo"
    with pytest.raises(ac.AuthError):
        ac.parse_authorization("Foo,", strict=True)
    secret = "QWxhZGRpbjpvcGVuIHNlc2FtZQ"
    with pytest.raises(old.AuthError, match=secret):
        old.decode_basic("Basic " + secret + "!")
    with pytest.raises(ac.AuthError) as caught:
        ac.decode_basic("Basic " + secret + "!")
    assert secret not in str(caught.value)
    with pytest.raises(UnicodeEncodeError):
        old.encode_ext_value("\ud800")
    assert "QWxh" in repr(old.parse_authorization("Basic QWxh"))
    assert "QWxh" not in repr(ac.parse_authorization("Basic QWxh"))
    with pytest.raises(ac.AuthError, match="not valid base64"):
        ac.decode_basic("Basic dTpw====")
    if sys.version_info < (3, 13):
        assert old.decode_basic("Basic dTpw====") == ("u", "p")
