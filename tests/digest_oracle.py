"""The Digest challenge the oracle tests send, and the check of the credentials they get."""

from __future__ import annotations

import authchallenge as ac

DIGEST = {
    "realm": "http-auth@example.org",
    "qop": "auth, auth-int",
    "algorithm": "SHA-256",
    "nonce": "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
    "opaque": "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
}  # the challenge of RFC 7616 section 3.9.1
USER, PASSWORD, URI = "Mufasa", "Circle of Life", "/dir/index.html"


def check_digest_credentials(
    header: str, uri: str = URI, algorithm: str = "SHA-256", strict: bool = True
) -> dict[str, str]:
    params = ac.parse_authorization(header, strict=strict).params
    assert params["username"] == USER and params["uri"] == uri
    for name in ("realm", "nonce", "opaque"):
        assert params[name] == DIGEST[name]
    assert params["qop"] == "auth" and params["nc"] == "00000001"
    assert params.get("algorithm", algorithm).upper() == algorithm
    return params
