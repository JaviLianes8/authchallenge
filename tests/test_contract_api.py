"""The stable 1.0 surface: signatures, wrong-type errors, bounded messages, hidden secrets."""

from __future__ import annotations

import inspect
import pickle
from collections.abc import Callable
from typing import Any

import pytest

import authchallenge as ac

# Parameter names, kinds and defaults are part of the promise: callers pass them by name.
SIGNATURES = {
    "parse_challenges": "(value, *, strict=False)",
    "parse_authorization": "(value, *, strict=False)",
    "parse_auth_info": "(value, *, strict=False, scheme=None)",
    "build_challenge": "(scheme, params=None, token68=None)",
    "build_authorization": "(scheme, params=None, token68=None)",
    "build_auth_info": "(params, *, scheme=None)",
    "build_bearer_challenge": (
        "(*, realm=None, scope=None, error=None, error_description=None, error_uri=None)"
    ),
    "encode_basic": "(user_id, password, *, charset='utf-8')",
    "decode_basic": "(credentials, *, charset='utf-8')",
    "encode_ext_value": "(text)",
    "decode_ext_value": "(value)",
    "select_challenge": "(challenges, *schemes)",
}


def _bare(function: Callable[..., Any]) -> str:
    parameters = inspect.signature(function).parameters.values()
    plain = [p.replace(annotation=inspect.Parameter.empty) for p in parameters]
    return str(inspect.Signature(plain))


@pytest.mark.parametrize("name", sorted(SIGNATURES))
def test_signatures_are_pinned(name: str) -> None:
    assert _bare(getattr(ac, name)) == SIGNATURES[name]


def test_every_function_of_the_api_has_a_pinned_signature() -> None:
    functions = {n for n in ac.__all__ if inspect.isfunction(getattr(ac, n))}
    assert functions == set(SIGNATURES)


def test_result_fields_are_pinned() -> None:
    for cls in (ac.Challenge, ac.Credentials):
        assert [f.name for f in cls.__dataclass_fields__.values()] == [
            "scheme",
            "token68",
            "params",
        ]
        assert cls("X") == cls("X", None, {})


@pytest.mark.parametrize("name", ["AuthError", "Challenge", "Credentials"])
def test_public_classes_live_in_the_package(name: str) -> None:
    cls = getattr(ac, name)
    assert cls.__module__ == "authchallenge"
    assert pickle.loads(pickle.dumps(cls)) is cls


def test_results_pickle_and_compare_by_value() -> None:
    challenge = ac.parse_challenges('Basic realm="a"')[0]
    assert pickle.loads(pickle.dumps(challenge)) == challenge
    creds = ac.parse_authorization("Bearer abc")
    assert pickle.loads(pickle.dumps(creds)) == creds


# Deliberately wrong types: the checker would refuse these calls.
untyped: Any = ac
WRONG_TYPES: list[tuple[str, Callable[[], object], str]] = [
    ("int field", lambda: untyped.parse_challenges(5), "iterable of str"),
    ("bytes field", lambda: untyped.parse_challenges(b"Basic"), "latin-1"),
    ("bytearray info", lambda: untyped.parse_auth_info(bytearray(b"a=b")), "latin-1"),
    ("int line", lambda: untyped.parse_challenges(["Basic", 1]), "each field line"),
    ("int info line", lambda: untyped.parse_auth_info([None]), "each field line"),
    ("list credentials", lambda: untyped.parse_authorization(["Basic x"]), "Authorization value"),
    ("info scheme", lambda: untyped.parse_auth_info("a=b", scheme=1), "scheme"),
    ("build scheme", lambda: untyped.build_challenge(1), "scheme"),
    ("build params", lambda: untyped.build_challenge("X", [("a", "b")]), "mapping"),
    ("build empty list", lambda: untyped.build_authorization("X", []), "mapping"),
    ("params with token68", lambda: untyped.build_challenge("X", [("a", "b")], "t"), "mapping"),
    ("build name", lambda: untyped.build_challenge("X", {1: "a"}), "auth-param name"),
    ("build value", lambda: untyped.build_challenge("X", {"a": 1}), "value of 'a'"),
    ("build token68", lambda: untyped.build_authorization("X", token68=b"abc"), "token68"),
    ("info params", lambda: untyped.build_auth_info("a=b"), "mapping"),
    ("info builder scheme", lambda: untyped.build_auth_info({"a": "b"}, scheme=b"x"), "scheme"),
    ("bearer scope", lambda: untyped.build_bearer_challenge(scope=3), "scope"),
    ("bearer scope token", lambda: untyped.build_bearer_challenge(scope=["a", 2]), "scope token"),
    ("bearer realm", lambda: untyped.build_bearer_challenge(realm=3), "realm"),
    ("basic user", lambda: untyped.encode_basic(1, "p"), "user_id"),
    ("basic password", lambda: untyped.encode_basic("u", None), "password"),
    ("basic charset", lambda: untyped.encode_basic("u", "p", charset=8), "charset"),
    ("decode basic", lambda: untyped.decode_basic(None), "str or Credentials"),
    ("decode charset", lambda: untyped.decode_basic("Basic dTpw", charset=None), "charset"),
    ("ext encode", lambda: untyped.encode_ext_value(b"x"), "text"),
    ("ext decode", lambda: untyped.decode_ext_value(None), "value"),
    ("select scheme", lambda: untyped.select_challenge([], 1), "scheme"),
    (
        "select item",
        lambda: untyped.select_challenge([ac.Credentials("Basic")], "basic"),
        "Challenge",
    ),
]


@pytest.mark.parametrize(("label", "call", "words"), WRONG_TYPES, ids=[w[0] for w in WRONG_TYPES])
def test_wrong_types_raise_type_error(label: str, call: Callable[[], object], words: str) -> None:
    with pytest.raises(TypeError, match=words) as caught:
        call()
    assert not isinstance(caught.value, ac.AuthError)


HUGE = "x" * 100_000
SECRET = "c2VjcmV0dXNlcjpzZWNyZXRwYXNzd29yZA" * 10
LONG_MESSAGES: list[Callable[[], object]] = [
    lambda: ac.build_challenge("a b" + HUGE),
    lambda: ac.build_challenge("X", {HUGE + " ": "v"}),
    lambda: ac.build_challenge("X", {HUGE: "v", HUGE.upper(): "w"}),
    lambda: ac.build_challenge("Digest", {"realm": "r", "algorithm": HUGE + " "}),
    lambda: ac.parse_challenges(f'Basic realm="a", {HUGE}="x" junk', strict=True),
    lambda: ac.parse_challenges(f'Basic realm="a", {HUGE}="x", {HUGE}=y', strict=True),
    lambda: ac.parse_challenges(f'Basic realm="a", Basic, {HUGE}=x', strict=True),
    lambda: ac.parse_auth_info(f"{HUGE}=1 junk", strict=True, scheme="Digest"),
    lambda: ac.decode_ext_value(HUGE),
    lambda: ac.decode_ext_value(HUGE + "''a"),
    lambda: ac.encode_basic("u", "p", charset=HUGE),
    lambda: ac.decode_basic(HUGE + " dTpw"),
    lambda: ac.decode_basic(ac.Credentials(HUGE, "dTpw")),
]


@pytest.mark.parametrize("call", LONG_MESSAGES)
def test_messages_quote_at_most_forty_characters_of_input(call: Callable[[], object]) -> None:
    with pytest.raises(ac.AuthError) as caught:
        call()
    message = str(caught.value)
    assert "x" * 41 not in message.lower() and len(message) < 200, message


SECRET_CALLS: list[Callable[[], object]] = [
    lambda: ac.decode_basic(SECRET),
    lambda: ac.decode_basic("Basic " + SECRET + "!"),
    lambda: ac.decode_basic("Basic " + SECRET),
    lambda: ac.decode_basic(ac.Credentials("Basic", SECRET + "%")),
    lambda: ac.build_authorization("Bearer", token68=SECRET + " "),
    lambda: ac.build_authorization("Basic", token68=SECRET),
    lambda: ac.parse_authorization("Basic " + SECRET, strict=True),
    lambda: ac.parse_authorization("Basic " + SECRET + " x", strict=True),
]


@pytest.mark.parametrize("call", SECRET_CALLS)
def test_messages_never_quote_a_token68(call: Callable[[], object]) -> None:
    with pytest.raises(ac.AuthError) as caught:
        call()
    assert SECRET[:8] not in str(caught.value)


def test_credentials_repr_hides_the_token68_only() -> None:
    creds = ac.parse_authorization("Basic " + SECRET)
    assert SECRET[:8] not in repr(creds) and "token68=<hidden>" in repr(creds)
    assert creds.token68 == SECRET
    digest = ac.Credentials("Digest", params={"username": "u"})
    assert repr(digest) == "Credentials(scheme='Digest', token68=None, params={'username': 'u'})"
    assert repr(ac.Challenge("Negotiate", "abc")) == (
        "Challenge(scheme='Negotiate', token68='abc', params={})"
    )


def test_a_lone_surrogate_is_an_auth_error_everywhere() -> None:
    for call in (
        lambda: ac.encode_ext_value("\ud800"),
        lambda: ac.encode_basic("\udfff", "p"),
        lambda: ac.build_challenge("X", {"a": "\ud800"}),
        lambda: ac.parse_challenges('Basic realm="\ud800"', strict=True),
    ):
        with pytest.raises(ac.AuthError):
            call()


def test_str_subclasses_are_accepted() -> None:
    class Text(str):
        pass

    assert ac.parse_challenges(Text('Basic realm="a"'))[0].params == {"realm": "a"}
    assert ac.build_challenge(Text("Basic"), {Text("realm"): Text("a")}) == 'Basic realm="a"'
