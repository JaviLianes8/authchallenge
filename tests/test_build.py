import pytest

from authchallenge import (
    AuthError,
    build_authorization,
    build_challenge,
    parse_authorization,
    parse_challenges,
)


def test_build_bare_scheme() -> None:
    assert build_challenge("Negotiate") == "Negotiate"


def test_build_challenge_with_params_quotes_only_when_needed() -> None:
    result = build_challenge("Digest", {"realm": "my zone", "algorithm": "MD5"})
    assert result == 'Digest realm="my zone", algorithm=MD5'


def test_build_challenge_with_token68() -> None:
    assert build_challenge("Negotiate", token68="a87421bff==") == "Negotiate a87421bff=="


def test_build_escapes_quotes_in_values() -> None:
    assert build_challenge("Basic", {"realm": 'a"b'}) == r'Basic realm="a\"b"'


def test_build_rejects_both_token68_and_params() -> None:
    with pytest.raises(AuthError):
        build_challenge("Negotiate", {"realm": "x"}, token68="abc")


def test_build_rejects_invalid_scheme() -> None:
    with pytest.raises(AuthError):
        build_challenge("bad scheme")


def test_build_rejects_invalid_token68() -> None:
    with pytest.raises(AuthError):
        build_challenge("Negotiate", token68='not valid"')


def test_build_rejects_invalid_param_name() -> None:
    with pytest.raises(AuthError):
        build_challenge("Basic", {"bad name": "x"})


def test_challenge_round_trip_through_parse() -> None:
    header = build_challenge("Digest", {"realm": "a, b", "qop": "auth"})
    (challenge,) = parse_challenges(header)
    assert challenge.scheme == "Digest"
    assert challenge.params == {"realm": "a, b", "qop": "auth"}


def test_authorization_round_trip_token68() -> None:
    line = build_authorization("Basic", token68="QWxhZGRpbjpvcGVu==")
    creds = parse_authorization(line)
    assert creds.scheme == "Basic"
    assert creds.token68 == "QWxhZGRpbjpvcGVu=="


def test_authorization_round_trip_params() -> None:
    line = build_authorization("Digest", {"username": "Mufasa", "uri": "/a/b"})
    creds = parse_authorization(line)
    assert creds.params == {"username": "Mufasa", "uri": "/a/b"}
