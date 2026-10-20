"""Independent implementations as oracles: real HTTP clients and servers, run live.

curl (the program), httpx, requests, werkzeug and the standard library's urllib each
parse our challenges or write credentials of their own; the library must read their
output and they must read ours. Each test skips when its oracle is not installed.
"""

from __future__ import annotations

import random
import shutil
import subprocess
import threading
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import authchallenge as ac

DIGEST = {
    "realm": "http-auth@example.org",
    "qop": "auth, auth-int",
    "algorithm": "SHA-256",
    "nonce": "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
    "opaque": "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
}  # the challenge of RFC 7616 section 3.9.1
USER, PASSWORD, URI = "Mufasa", "Circle of Life", "/dir/index.html"


def _check_digest_credentials(
    header: str, uri: str = URI, algorithm: str = "SHA-256", strict: bool = True
) -> dict[str, str]:
    params = ac.parse_authorization(header, strict=strict).params
    assert params["username"] == USER and params["uri"] == uri
    for name in ("realm", "nonce", "opaque"):
        assert params[name] == DIGEST[name]
    assert params["qop"] == "auth" and params["nc"] == "00000001"
    assert params.get("algorithm", algorithm).upper() == algorithm
    return params


@pytest.fixture
def server() -> Iterator[tuple[str, list[str]]]:
    """A local server that answers 401 with our challenge and records Authorization."""
    seen: list[str] = []
    # curl on Windows does Digest through the system (SSPI), which offers MD5 only.
    challenge = ac.build_challenge("Digest", {**DIGEST, "algorithm": "MD5"})

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            header = self.headers.get("Authorization")
            if header is None:
                self.send_response(401)
                self.send_header("WWW-Authenticate", challenge)
            else:
                seen.append(header)
                self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}", seen
    finally:
        httpd.shutdown()
        httpd.server_close()


def _curl(*args: str) -> None:
    curl = shutil.which("curl")
    if curl is None:
        pytest.skip("curl is not installed")
    done = subprocess.run([curl, "-s", "-o", "-", *args], capture_output=True, timeout=60)
    assert done.returncode == 0, done.stderr


def test_curl_basic_matches_encode_basic(server: tuple[str, list[str]]) -> None:
    url, seen = server
    for user, password in [("Aladdin", "open sesame"), ("a", ""), ("u-1", "p:a:s s")]:
        _curl("-u", f"{user}:{password}", url + "/basic")
        assert seen[-1] == ac.encode_basic(user, password)
        assert ac.decode_basic(seen[-1]) == (user, password)


def test_curl_bearer_is_read_strictly(server: tuple[str, list[str]]) -> None:
    url, seen = server
    _curl("--oauth2-bearer", "mF_9.B5f-4.1JqM", url + "/bearer")
    assert ac.parse_authorization(seen[-1], strict=True) == ac.Credentials(
        "Bearer", "mF_9.B5f-4.1JqM"
    )


def test_curl_answers_our_digest_challenge(server: tuple[str, list[str]]) -> None:
    url, seen = server
    _curl("--digest", "-u", f"{USER}:{PASSWORD}", url + URI)
    assert len(seen) == 1
    try:
        params = _check_digest_credentials(seen[0], algorithm="MD5")
    except ac.AuthError as error:
        # The Windows build writes qop="auth", which RFC 7616 section 3.4 tells senders
        # not to quote: strict mode names it, tolerant mode reads the same values.
        assert "qop parameter must not be quoted" in str(error)
        params = _check_digest_credentials(seen[0], algorithm="MD5", strict=False)
    assert len(params["response"]) == 32  # an MD5 digest


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
    _check_digest_credentials(sent[0])


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
    try:
        _check_digest_credentials(header, algorithm="MD5")
    except ac.AuthError as error:
        # urllib quotes algorithm, as requests does.
        assert "algorithm parameter must not be quoted" in str(error)
        _check_digest_credentials(header, algorithm="MD5", strict=False)
