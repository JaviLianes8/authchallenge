"""Build challenge, credentials and Authentication-Info field values safely (RFC 9110)."""

from __future__ import annotations

from collections.abc import Mapping

from ._grammar import is_field_text, is_token, is_token68, quote
from ._model import AuthError
from ._scan import Param
from ._schemes import DIGEST_BARE, DIGEST_QUOTED, check


def _must_quote(scheme: str, kind: str, name: str, value: str) -> bool:
    key = scheme.lower()
    if key == "digest" and name in DIGEST_BARE[kind]:
        if not is_token(value):
            raise AuthError(f"the Digest {name} parameter must be a token: {value!r}")
        return False
    if name == "realm" or key in ("basic", "bearer"):
        return True
    if key == "digest" and name in DIGEST_QUOTED[kind]:
        return True
    return not is_token(value)


def _render_params(scheme: str, kind: str, params: Mapping[str, str]) -> tuple[str, list[Param]]:
    rendered: list[str] = []
    read: list[Param] = []
    for key, value in params.items():
        if not isinstance(key, str) or not is_token(key):
            raise AuthError(f"invalid auth-param name: {key!r}")
        name = key.lower()
        if any(seen.name == name for seen in read):
            raise AuthError(f"duplicate auth-param name: {key!r}")
        if not isinstance(value, str) or not is_field_text(value):
            raise AuthError(
                f"the value of {key!r} may hold only tab, space and visible ASCII; "
                "send other text as an RFC 8187 ext-value (see encode_ext_value)"
            )
        quoted = _must_quote(scheme, kind, name, value)
        rendered.append(f"{key}={quote(value) if quoted else value}")
        read.append(Param(name, value, quoted, 0))
    return ", ".join(rendered), read


def render(scheme: str, params: Mapping[str, str] | None, token68: str | None, kind: str) -> str:
    """Render a challenge or credentials, refusing anything strict parsing would refuse."""
    if not isinstance(scheme, str) or not is_token(scheme):
        raise AuthError(f"invalid auth-scheme: {scheme!r}")
    if token68 is not None and params:
        raise AuthError("use either token68 or params, not both")
    if token68 is not None:
        if not isinstance(token68, str) or not is_token68(token68):
            raise AuthError(f"invalid token68: {token68!r}")
        check(scheme, kind, token68, [])
        return f"{scheme} {token68}"
    text, read = _render_params(scheme, kind, params or {})
    check(scheme, kind, None, read)
    return f"{scheme} {text}" if text else scheme


def build_challenge(
    scheme: str,
    params: Mapping[str, str] | None = None,
    token68: str | None = None,
) -> str:
    """Build one challenge for a WWW-Authenticate or Proxy-Authenticate field.

    Values are quoted when they are not tokens and whenever the scheme's sender rules
    say so (realm always, every Basic and Bearer param as their RFC examples do, the
    Digest lists of RFC 7616). Raises
    `AuthError` for invalid names or values and for what Basic, Bearer or Digest forbid,
    so the result always passes `parse_challenges(..., strict=True)`.
    """
    return render(scheme, params, token68, "challenge")


def build_authorization(
    scheme: str,
    params: Mapping[str, str] | None = None,
    token68: str | None = None,
) -> str:
    """Build an Authorization or Proxy-Authorization field value, under the same rules."""
    return render(scheme, params, token68, "credentials")


def build_auth_info(params: Mapping[str, str], *, scheme: str | None = None) -> str:
    """Build an Authentication-Info or Proxy-Authentication-Info field value.

    Give the `scheme` of the request's credentials to apply its rules (Digest quotes
    nextnonce, rspauth and cnonce, writes qop and nc bare, and checks nc).
    """
    text, read = _render_params(scheme or "", "info", params)
    if not text:
        raise AuthError("Authentication-Info needs at least one auth-param")
    if scheme is not None:
        check(scheme, "info", None, read)
    return text
