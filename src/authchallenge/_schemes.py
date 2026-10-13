"""Rules of the registered schemes: Basic (RFC 7617), Bearer (RFC 6750), Digest (RFC 7616)."""

from __future__ import annotations

import re
from collections.abc import Sequence

from ._basic import split_user_pass
from ._extvalue import decode_ext_value
from ._model import AuthError
from ._scan import Param

# RFC 7616 sections 3.3, 3.4 and 3.5: values a sender must quote, and values it must not.
DIGEST_QUOTED = {
    "challenge": frozenset({"realm", "domain", "nonce", "opaque", "qop"}),
    "credentials": frozenset({"username", "realm", "nonce", "uri", "response", "cnonce", "opaque"}),
    "info": frozenset({"nextnonce", "rspauth", "cnonce"}),
}
DIGEST_BARE = {
    "challenge": frozenset({"stale", "algorithm"}),
    "credentials": frozenset({"algorithm", "qop", "nc"}),
    "info": frozenset({"qop", "nc"}),
}
# RFC 6750 section 3: scope tokens, error and error_description, error_uri.
_SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]+")
_NQSCHAR = re.compile(r"[\x20\x21\x23-\x5b\x5d-\x7e]*")
_URI_CHARS = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]*")
_NC = re.compile(r"[0-9A-Fa-f]{8}")


def _values(params: Sequence[Param]) -> dict[str, Param]:
    return {param.name: param for param in params}


def _require(scheme: str, found: dict[str, Param], names: Sequence[str]) -> None:
    for name in names:
        if name not in found:
            raise AuthError(f"{scheme} needs the {name!r} parameter")


def _basic(kind: str, token68: str | None, found: dict[str, Param]) -> None:
    if kind == "credentials":
        if token68 is None:
            raise AuthError("Basic credentials are a token68")
        split_user_pass(token68, "latin-1")
        return
    _require("Basic", found, ["realm"])
    charset = found.get("charset")
    if charset is not None and charset.value.lower() != "utf-8":
        raise AuthError("the Basic charset parameter only allows 'UTF-8'")


def _bearer(kind: str, token68: str | None, found: dict[str, Param]) -> None:
    if kind == "credentials":
        if token68 is None:
            raise AuthError("Bearer credentials are a b64token")
        return
    if not found:
        raise AuthError("a Bearer challenge needs at least one auth-param")
    scope = found.get("scope")
    if scope is not None and not all(_SCOPE_TOKEN.fullmatch(s) for s in scope.value.split(" ")):
        raise AuthError("the Bearer scope holds a character RFC 6750 does not allow")
    for name, pattern in (("error", _NQSCHAR), ("error_description", _NQSCHAR)):
        if name in found and not pattern.fullmatch(found[name].value):
            raise AuthError(f"the Bearer {name} holds a character RFC 6750 does not allow")
    if "error_uri" in found and not _URI_CHARS.fullmatch(found["error_uri"].value):
        raise AuthError("the Bearer error_uri holds a character RFC 6750 does not allow")


def _flag(found: dict[str, Param], name: str) -> None:
    if name in found and found[name].value.lower() not in ("true", "false"):
        raise AuthError(f"the Digest {name} parameter is 'true' or 'false'")


def _digest(kind: str, token68: str | None, found: dict[str, Param]) -> None:
    if token68 is not None:
        raise AuthError("Digest uses auth-params, not a token68")
    for name, param in found.items():
        if name in DIGEST_QUOTED[kind] and not param.quoted:
            raise AuthError(f"the Digest {name} parameter must be a quoted-string")
        if name in DIGEST_BARE[kind] and param.quoted:
            raise AuthError(f"the Digest {name} parameter must not be quoted")
    if "nc" in found and not _NC.fullmatch(found["nc"].value):
        raise AuthError("the Digest nc parameter is exactly 8 hexadecimal digits")
    charset = found.get("charset")
    if charset is not None and charset.value.lower() != "utf-8":
        raise AuthError("the Digest charset parameter only allows 'UTF-8'")
    _flag(found, "stale")
    _flag(found, "userhash")
    if kind == "challenge":
        # The response of section 3.4.1 is computed from realm and nonce; qop is a MUST.
        _require("Digest", found, ["realm", "nonce", "qop"])
    elif kind == "credentials":
        _digest_credentials(found)
    elif "qop" in found:
        _require("Digest", found, ["rspauth", "cnonce", "nc"])


def _digest_credentials(found: dict[str, Param]) -> None:
    if ("username" in found) == ("username*" in found):
        raise AuthError("Digest credentials carry exactly one of username and username*")
    if "username*" in found:
        if found["username*"].quoted:
            raise AuthError("the Digest username* parameter is an ext-value, not quoted")
        decode_ext_value(found["username*"].value)
    _require("Digest", found, ["realm", "nonce", "uri", "response", "cnonce", "nc"])


def check(scheme: str, kind: str, token68: str | None, params: Sequence[Param]) -> None:
    """Raise AuthError if a challenge, credentials or Authentication-Info breaks a rule.

    `kind` is "challenge", "credentials" or "info". Rules of RFC 9110 apply to every
    scheme; Basic, Bearer and Digest add their own. Unknown schemes only get the former.
    """
    found = _values(params)
    realm = found.get("realm")
    if kind == "challenge" and realm is not None and not realm.quoted:
        raise AuthError("the realm parameter must be a quoted-string")
    rules = {"basic": _basic, "bearer": _bearer, "digest": _digest}.get(scheme.lower())
    if rules is not None and (kind != "info" or rules is _digest):
        rules(kind, token68, found)
