from __future__ import annotations

from authchallenge import parse_authorization, parse_challenges


def test_basic_realm_challenge() -> None:
    (challenge,) = parse_challenges('Basic realm="WallyWorld"')
    assert challenge.scheme == "Basic"
    assert challenge.token68 is None
    assert challenge.params == {"realm": "WallyWorld"}


def test_bearer_challenge_with_several_params() -> None:
    (challenge,) = parse_challenges('Bearer realm="example", error="invalid_token"')
    assert challenge.scheme == "Bearer"
    assert challenge.params == {"realm": "example", "error": "invalid_token"}


def test_digest_with_many_params_and_a_comma_inside_a_quoted_value() -> None:
    header = (
        'Digest realm="http-auth@example.org", qop="auth, auth-int", '
        'algorithm=MD5, nonce="abc123", opaque="xyz"'
    )
    (challenge,) = parse_challenges(header)
    assert challenge.scheme == "Digest"
    assert challenge.params["realm"] == "http-auth@example.org"
    assert challenge.params["qop"] == "auth, auth-int"
    assert challenge.params["algorithm"] == "MD5"
    assert challenge.params["nonce"] == "abc123"
    assert challenge.params["opaque"] == "xyz"


def test_multiple_challenges_in_one_header() -> None:
    header = 'Basic realm="simple", Newauth realm="apps", type=1, title="Login"'
    basic, newauth = parse_challenges(header)
    assert basic.scheme == "Basic"
    assert basic.params == {"realm": "simple"}
    assert newauth.scheme == "Newauth"
    assert newauth.params == {"realm": "apps", "type": "1", "title": "Login"}


def test_token68_challenge() -> None:
    (challenge,) = parse_challenges("Negotiate a87421bff012e83c==")
    assert challenge.scheme == "Negotiate"
    assert challenge.token68 == "a87421bff012e83c=="
    assert challenge.params == {}


def test_bare_scheme_before_a_parametrised_one() -> None:
    first, second = parse_challenges('Basic, Bearer realm="x"')
    assert first.scheme == "Basic"
    assert first.token68 is None and first.params == {}
    assert second.scheme == "Bearer"


def test_param_names_are_lowercased() -> None:
    (challenge,) = parse_challenges('Basic REALM="x"')
    assert challenge.params == {"realm": "x"}


def test_bws_around_the_equals_sign() -> None:
    (challenge,) = parse_challenges('Basic realm = "x"')
    assert challenge.params == {"realm": "x"}


def test_malformed_header_is_tolerated() -> None:
    assert parse_challenges("") == []
    assert parse_challenges("   ") == []
    # A fragment with no scheme yields nothing rather than raising.
    assert parse_challenges('realm="x"') == []


def test_parse_basic_authorization_token68() -> None:
    creds = parse_authorization("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
    assert creds.scheme == "Basic"
    assert creds.token68 == "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
    assert creds.params == {}


def test_parse_bearer_authorization_token68() -> None:
    creds = parse_authorization("Bearer mF_9.B5f-4.1JqM")
    assert creds.scheme == "Bearer"
    assert creds.token68 == "mF_9.B5f-4.1JqM"


def test_parse_digest_authorization_params() -> None:
    header = 'Digest username="Mufasa", realm="test", uri="/dir/index.html", response="6629fae"'
    creds = parse_authorization(header)
    assert creds.scheme == "Digest"
    assert creds.token68 is None
    assert creds.params["username"] == "Mufasa"
    assert creds.params["uri"] == "/dir/index.html"


def test_parse_authorization_tolerates_empty() -> None:
    assert parse_authorization("").scheme == ""
