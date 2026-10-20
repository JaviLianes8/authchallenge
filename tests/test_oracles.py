"""Independent implementations as oracles: HTTP client and server libraries, run live.

httpx, requests, werkzeug and the standard library's urllib each parse our challenges
or write credentials of their own; the library must read their output and they must
read ours. Each test skips when its oracle is not installed.
"""

from __future__ import annotations

import random
import urllib.request

import pytest
from digest_oracle import DIGEST, PASSWORD, URI, USER, check_digest_credentials

import authchallenge as ac


def test_httpx_answers_our_digest_challenge() -> None:
    httpx = pytest.importorskip("httpx")
    challenge = ac.build_challenge("Digest", DIGEST)
    sent: list[str] = []

    def handler(request: object) -> object:
        header = request.headers.get("authorization")  # type: ignore[attr-defined]
        if header:
            sent.append(header)
            return httpx.Response(200)
        return httpx.Response(401, headers={"WWW-Authenticate": challenge})

    auth = httpx.DigestAuth(USER, PASSWORD)
    with httpx.Client(transport=httpx.MockTransport(handler), auth=auth) as client:
        assert client.get("http://www.example.org" + URI).status_code == 200
    check_digest_credentials(sent[0])


def test_requests_digest_quotes_what_rfc_7616_says_to_leave_bare() -> None:
    auth_module = pytest.importorskip("requests.auth")
    auth = auth_module.HTTPDigestAuth(USER, PASSWORD)
    auth.init_per_thread_state()
    auth._thread_local.chal = ac.parse_challenges(ac.build_challenge("Digest", DIGEST))[0].params
    header = auth.build_digest_header("GET", "http://www.example.org" + URI)
    # requests writes algorithm="SHA-256" and qop="auth": strict mode names the first.
    with pytest.raises(ac.AuthError, match="algorithm parameter must not be quoted"):
        ac.parse_authorization(header, strict=True)
    params = ac.parse_authorization(header).params
    assert params["qop"] == "auth" and params["algorithm"] == "SHA-256"
    assert params["username"] == USER and params["nc"] == "00000001"


@pytest.mark.parametrize("seed", [3, 4])
def test_requests_and_encode_basic_agree_on_latin_1(seed: int) -> None:
    auth_module = pytest.importorskip("requests.auth")
    rng = random.Random(seed)
    for _ in range(2000):
        user = "".join(chr(rng.choice([rng.randint(32, 126), rng.randint(160, 255)])) for _ in "ab")
        password = "".join(chr(rng.randint(160, 255)) for _ in range(rng.randint(0, 6)))
        user = user.replace(":", "")
        expected = auth_module._basic_auth_str(user, password)
        assert ac.encode_basic(user, password, charset="latin-1") == expected
        assert ac.decode_basic(expected, charset="latin-1") == (user, password)


def test_werkzeug_reads_our_challenges_and_credentials() -> None:
    datastructures = pytest.importorskip("werkzeug.datastructures")
    rng = random.Random(5)
    for _ in range(2000):
        params = {f"p{i}": "".join(rng.choice("ab ,=;/") for _ in range(4)) for i in range(3)}
        params["realm"] = "".join(rng.choice("xy z") for _ in range(5))
        read = datastructures.WWWAuthenticate.from_header(ac.build_challenge("Newauth", params))
        assert (read.type, dict(read.parameters)) == ("newauth", params)
        creds = datastructures.Authorization.from_header(ac.build_authorization("Newauth", params))
        assert dict(creds.parameters) == params
    basic = datastructures.Authorization.from_header(ac.encode_basic("Aladdin", "open sesame"))
    assert (basic.username, basic.password) == ("Aladdin", "open sesame")


def test_werkzeug_challenges_are_read_tolerantly() -> None:
    datastructures = pytest.importorskip("werkzeug.datastructures")
    header = datastructures.WWWAuthenticate("basic", {"realm": "a b", "charset": "UTF-8"})
    assert ac.parse_challenges(header.to_header(), strict=True)[0].params["realm"] == "a b"
    bare = datastructures.WWWAuthenticate("bearer", {"realm": "api", "error": "invalid_token"})
    # werkzeug writes realm=api as a token, which RFC 9110 section 11.5 forbids senders.
    with pytest.raises(ac.AuthError, match="realm parameter must be a quoted-string"):
        ac.parse_challenges(bare.to_header(), strict=True)
    assert ac.parse_challenges(bare.to_header())[0].params == {
        "realm": "api",
        "error": "invalid_token",
    }


def test_urllib_splits_our_digest_challenge_the_same_way() -> None:
    rng = random.Random(6)
    for _ in range(2000):
        params = dict(DIGEST)
        params["opaque"] = "".join(rng.choice('ab ,="\\') for _ in range(8))
        header = ac.build_challenge("Digest", params)
        items = urllib.request.parse_http_list(header.split(" ", 1)[1])
        assert urllib.request.parse_keqv_list(items) == params or "\\" in params["opaque"]


def test_urllib_digest_handler_answers_our_challenge() -> None:
    manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    manager.add_password(None, "http://www.example.org/", USER, PASSWORD)
    handler = urllib.request.HTTPDigestAuthHandler(manager)
    request = urllib.request.Request("http://www.example.org" + URI)
    built = ac.build_challenge("Digest", {**DIGEST, "algorithm": "MD5"})
    header = "Digest " + str(
        handler.get_authorization(request, ac.parse_challenges(built)[0].params)
    )
    # urllib writes algorithm="MD5", which RFC 7616 section 3.4 tells senders not to quote.
    with pytest.raises(ac.AuthError, match="algorithm parameter must not be quoted"):
        check_digest_credentials(header, algorithm="MD5")
    check_digest_credentials(header, algorithm="MD5", strict=False)
