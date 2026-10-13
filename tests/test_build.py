from __future__ import annotations

import pytest

from authchallenge import (
    AuthError,
    build_auth_info,
    build_authorization,
    build_challenge,
    parse_auth_info,
    parse_authorization,
    parse_challenges,
)

DIGEST = {"realm": "a, b", "qop": "auth", "nonce": "n1", "algorithm": "SHA-256"}


def test_build_bare_scheme() -> None:
    assert build_challenge("Negotiate") == "Negotiate"


def test_values_are_quoted_only_when_they_are_not_tokens() -> None:
    result = build_challenge("Newauth", {"title": "my zone", "type": "1"})
    assert result == 'Newauth title="my zone", type=1'


def test_realm_is_always_quoted() -> None:
    assert build_challenge("Newauth", {"realm": "apps"}) == 'Newauth realm="apps"'


def test_basic_and_bearer_params_are_quoted() -> None:
    assert build_challenge("Basic", {"realm": "x", "charset": "UTF-8"}).endswith('"UTF-8"')
    assert build_challenge("Bearer", {"error": "invalid_token"}) == 'Bearer error="invalid_token"'


def test_digest_follows_the_sender_lists() -> None:
    header = build_challenge("Digest", DIGEST)
    assert header == 'Digest realm="a, b", qop="auth", nonce="n1", algorithm=SHA-256'


def test_digest_bare_params_must_be_tokens() -> None:
    with pytest.raises(AuthError, match="algorithm"):
        build_challenge("Digest", {**DIGEST, "algorithm": "SHA 256"})


def test_build_challenge_with_token68() -> None:
    assert build_challenge("Negotiate", token68="a87421bff==") == "Negotiate a87421bff=="


def test_build_escapes_quotes_and_backslashes_in_values() -> None:
    assert build_challenge("Newauth", {"realm": 'a"b\\c'}) == r'Newauth realm="a\"b\\c"'


def test_an_empty_value_is_an_empty_quoted_string() -> None:
    assert build_challenge("Newauth", {"x": ""}) == 'Newauth x=""'


@pytest.mark.parametrize("value", ["a\r\nX-Evil: 1", "a\nb", "a\rb", "a\x00b", "a\x7fb", "café"])
def test_values_that_could_break_the_header_are_refused(value: str) -> None:
    with pytest.raises(AuthError, match="visible ASCII"):
        build_challenge("Newauth", {"realm": value})
    with pytest.raises(AuthError):
        build_authorization("Newauth", {"x": value})


def test_a_tab_inside_a_value_is_kept_in_quotes() -> None:
    assert build_challenge("Newauth", {"x": "a\tb"}) == 'Newauth x="a\tb"'


def test_build_rejects_both_token68_and_params() -> None:
    with pytest.raises(AuthError):
        build_challenge("Negotiate", {"realm": "x"}, token68="abc")


@pytest.mark.parametrize("scheme", ["bad scheme", "", "Basic\r\n", 'a"b'])
def test_build_rejects_invalid_scheme(scheme: str) -> None:
    with pytest.raises(AuthError, match="auth-scheme"):
        build_challenge(scheme)


@pytest.mark.parametrize("token68", ['not valid"', "", "ab=c", "a b", "a\r\n"])
def test_build_rejects_invalid_token68(token68: str) -> None:
    with pytest.raises(AuthError, match="token68"):
        build_challenge("Negotiate", token68=token68)


@pytest.mark.parametrize("name", ["bad name", "", "a=b", "a\r\nb"])
def test_build_rejects_invalid_param_name(name: str) -> None:
    with pytest.raises(AuthError, match="name"):
        build_challenge("Newauth", {name: "x"})


def test_build_rejects_names_that_differ_only_in_case() -> None:
    with pytest.raises(AuthError, match="duplicate"):
        build_challenge("Newauth", {"realm": "a", "Realm": "b"})


def test_challenge_round_trip_through_strict_parse() -> None:
    header = build_challenge("Digest", DIGEST)
    (challenge,) = parse_challenges(header, strict=True)
    assert challenge.scheme == "Digest"
    assert challenge.params == DIGEST


def test_authorization_round_trip_token68() -> None:
    line = build_authorization("Basic", token68="QWxhZGRpbjpvcGVu")
    creds = parse_authorization(line, strict=True)
    assert (creds.scheme, creds.token68) == ("Basic", "QWxhZGRpbjpvcGVu")


def test_authorization_round_trip_params() -> None:
    line = build_authorization("Newauth", {"user": "Mufasa", "uri": "/a/b"})
    assert parse_authorization(line, strict=True).params == {"user": "Mufasa", "uri": "/a/b"}


def test_auth_info_builds_a_param_list() -> None:
    params = {"nextnonce": "abc", "qop": "auth", "rspauth": "d1", "cnonce": "c", "nc": "00000001"}
    text = build_auth_info(params, scheme="Digest")
    assert text == 'nextnonce="abc", qop=auth, rspauth="d1", cnonce="c", nc=00000001'
    assert parse_auth_info(text, strict=True, scheme="Digest") == params


def test_auth_info_without_scheme_quotes_only_what_needs_it() -> None:
    assert build_auth_info({"a": "b c", "d": "e"}) == 'a="b c", d=e'


def test_auth_info_needs_a_param() -> None:
    with pytest.raises(AuthError, match="at least one"):
        build_auth_info({})
