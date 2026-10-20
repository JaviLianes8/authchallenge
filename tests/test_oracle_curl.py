"""curl, the program, as an oracle: it answers our challenges from a local server.

The test skips when curl is not on PATH.
"""

from __future__ import annotations

import shutil
import subprocess
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from digest_oracle import DIGEST, PASSWORD, URI, USER, check_digest_credentials

import authchallenge as ac


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


def _curl(*args: str, seen: list[str] | None = None) -> None:
    curl = shutil.which("curl")
    if curl is None:
        pytest.skip("curl is not installed")
    done = subprocess.run([curl, "-sS", "-o", "-", *args], capture_output=True, timeout=60)
    if done.returncode == 67 and seen == []:
        # Windows builds hand Digest to the system (SSPI); some accounts refuse it locally
        # ("Login denied") before any credentials are sent: nothing to compare.
        pytest.skip(f"this curl refused to compute Digest: {done.stderr!r}")
    assert done.returncode == 0, (done.returncode, done.stderr)


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
    _curl("--digest", "-u", f"{USER}:{PASSWORD}", url + URI, seen=seen)
    assert len(seen) == 1
    try:
        params = check_digest_credentials(seen[0], algorithm="MD5")
    except ac.AuthError as error:
        # The Windows build writes qop="auth", which RFC 7616 section 3.4 tells senders
        # not to quote: strict mode names it, tolerant mode reads the same values.
        assert "qop parameter must not be quoted" in str(error)
        params = check_digest_credentials(seen[0], algorithm="MD5", strict=False)
    assert len(params["response"]) == 32  # an MD5 digest
