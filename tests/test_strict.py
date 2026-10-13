"""Strict parsing: each grammar rule of RFC 9110 section 11 raises with its reason."""

from __future__ import annotations

import pytest

from authchallenge import AuthError, parse_auth_info, parse_authorization, parse_challenges


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ('Basic\r\n realm="foo"', "obsolete line folding at offset 5"),
        ('Basic realm="a\x00"', "not allowed in a field value at offset 14"),
        ('Basic realm="a\nb"', "not allowed"),
        ('Basic realm="a\x7f"', "not allowed"),
        ('Basic realm="Ā"', "not allowed"),
        ('Basic realm="basic', "unterminated quoted-string at offset 12"),
        ('Basic realm="x" extra', "unexpected text after the value of 'realm' at offset 16"),
        ('Digest qop="auth"x', "unexpected text after the value of 'qop'"),
        ("Basic realm=\\f\\o\\o", "expected a token68 or an auth-param at offset 6"),
        ('Basic, realm="foo"', "auth-param 'realm' outside a challenge at offset 7"),
        ('realm="foo"', "auth-param 'realm' outside a challenge at offset 0"),
        ("Newauth abc=, x=y", "auth-param 'x' outside a challenge"),
        ('Basic\trealm="x"', "the auth-scheme must be followed by spaces at offset 5"),
        ('Basic \trealm="x"', "followed by spaces"),
        ("Basic/x", "expected a space after the auth-scheme at offset 5"),
        ('=x, Basic realm="r"', "expected an auth-scheme or auth-param at offset 0"),
        ('Basic realm="a", Realm="b"', "duplicate auth-param 'realm' at offset 17"),
        ("Newauth realm=apps", "realm parameter must be a quoted-string"),
        ("Basic realm='foo'", "realm parameter must be a quoted-string"),
        ("", "no challenge"),
        (" , ,", "no challenge"),
    ],
)
def test_strict_reasons(value: str, reason: str) -> None:
    with pytest.raises(AuthError, match=reason.replace("(", r"\(")):
        parse_challenges(value, strict=True)


@pytest.mark.parametrize(
    "value",
    [
        'Basic realm="x"',
        'Basic , realm="foo"',
        'Negotiate \t, Bearer realm="x"',
        ', Newauth realm="a" , , b=1 ,',
        "Negotiate a87421bff012e83c==, A, B",
        'Newauth x="\té", realm=""',
        'Newauth realm = "x"',
    ],
)
def test_strict_accepts_valid_values(value: str) -> None:
    assert parse_challenges(value, strict=True)


def test_strict_errors_are_value_errors() -> None:
    with pytest.raises(ValueError):
        parse_challenges("Basic realm=x", strict=True)


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("", "start with an auth-scheme"),
        (", Basic QQ==", "start with an auth-scheme"),
        ("Basic QQ==, Basic QQ==", "only one credentials is allowed at offset 12"),
        ("Basic QQ==,", "nothing may follow the token68"),
        ("Newauth QQ== x", "expected a token68 or an auth-param"),
        ("Newauth a=1, a=2", "duplicate"),
    ],
)
def test_strict_credentials(value: str, reason: str) -> None:
    with pytest.raises(AuthError, match=reason):
        parse_authorization(value, strict=True)


def test_strict_credentials_accept_a_trailing_comma_after_params() -> None:
    assert parse_authorization("Newauth a=1,", strict=True).params == {"a": "1"}


@pytest.mark.parametrize(
    ("value", "reason"),
    [("qop=auth, rspauth", "expected an auth-param"), ("a=1, A=2", "duplicate")],
)
def test_strict_auth_info(value: str, reason: str) -> None:
    with pytest.raises(AuthError, match=reason):
        parse_auth_info(value, strict=True)
