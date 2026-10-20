"""Build challenge, credentials and Authentication-Info field values safely (RFC 9110)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._grammar import is_field_text, is_token, is_token68, need_str, quote, shown
from ._model import AuthError
from ._scan import Param
from ._schemes import DIGEST_BARE, DIGEST_QUOTED, check


def _must_quote(scheme: str, kind: str, name: str, value: str) -> bool:
    key = scheme.lower()
    if key == "digest" and name in DIGEST_BARE[kind]:
        if not is_token(value):
            raise AuthError(f"the Digest {name} parameter must be a token: {shown(value)}")
        return False
    if name == "realm" or key in ("basic", "bearer"):
        return True
    if key == "digest" and name in DIGEST_QUOTED[kind]:
        return True
    return not is_token(value)


def _render_params(scheme: str, kind: str, params: Any) -> tuple[str, list[Param]]:
    if not isinstance(params, Mapping):
        raise TypeError(f"params must be a mapping, not {type(params).__name__}")
    rendered: list[str] = []
    read: list[Param] = []
    seen: set[str] = set()
    for key, value in params.items():
        if not is_token(need_str(key, "an auth-param name")):
            raise AuthError(f"invalid auth-param name: {shown(key)}")
        name = key.lower()
        if name in seen:
            raise AuthError(f"duplicate auth-param name: {shown(key)}")
        if not is_field_text(need_str(value, f"the value of {shown(key)}")):
            raise AuthError(
                f"the value of {shown(key)} may hold only tab, space and visible ASCII; "
                "send other text as an RFC 8187 ext-value (see encode_ext_value)"
            )
        quoted = _must_quote(scheme, kind, name, value)
        rendered.append(f"{key}={quote(value) if quoted else value}")
        read.append(Param(name, value, quoted, 0))
        seen.add(name)
    return ", ".join(rendered), read


def render(scheme: str, params: Mapping[str, str] | None, token68: str | None, kind: str) -> str:
    """Render a challenge or credentials, refusing anything strict parsing would refuse."""
    if not is_token(need_str(scheme, "scheme")):
        raise AuthError(f"invalid auth-scheme: {shown(scheme)}")
    if params is not None and not isinstance(params, Mapping):
        raise TypeError(f"params must be a mapping, not {type(params).__name__}")
    if token68 is not None and params:
        raise AuthError("use either token68 or params, not both")
    if token68 is not None:
        # A token68 is often a secret (Basic, Bearer): the message never quotes it.
        if not is_token68(need_str(token68, "token68")):
            raise AuthError("invalid token68: letters, digits and -._~+/ then '=' padding only")
        check(scheme, kind, token68, [])
        return f"{scheme} {token68}"
    text, read = _render_params(scheme, kind, {} if params is None else params)
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
    so the result always passes `parse_challenges(..., strict=True)`. Arguments of the
    wrong type raise `TypeError`.

    >>> from authchallenge import build_challenge
    >>> build_challenge("Basic", {"realm": "WallyWorld", "charset": "UTF-8"})
    'Basic realm="WallyWorld", charset="UTF-8"'
    >>> build_challenge("Newauth", {"realm": "apps", "type": "1", "title": "Login Page"})
    'Newauth realm="apps", type=1, title="Login Page"'
    >>> build_challenge("Negotiate", token68="a87421bff012e83c==")
    'Negotiate a87421bff012e83c=='
    """
    return render(scheme, params, token68, "challenge")


def build_authorization(
    scheme: str,
    params: Mapping[str, str] | None = None,
    token68: str | None = None,
) -> str:
    """Build an Authorization or Proxy-Authorization field value, under the same rules.

    The result always passes `parse_authorization(..., strict=True)`.

    >>> from authchallenge import build_authorization
    >>> build_authorization("Bearer", token68="mF_9.B5f-4.1JqM")
    'Bearer mF_9.B5f-4.1JqM'
    >>> build_authorization("Newauth", {"user": "a b", "id": "7"})
    'Newauth user="a b", id=7'
    """
    return render(scheme, params, token68, "credentials")


def build_auth_info(params: Mapping[str, str], *, scheme: str | None = None) -> str:
    """Build an Authentication-Info or Proxy-Authentication-Info field value.

    Give the `scheme` of the request's credentials to apply its rules (Digest quotes
    nextnonce, rspauth and cnonce, writes qop and nc bare, and checks nc).

    >>> from authchallenge import build_auth_info
    >>> build_auth_info({"nextnonce": "47364c23"}, scheme="Digest")
    'nextnonce="47364c23"'
    >>> build_auth_info({"sid": "a1", "note": "two words"})
    'sid=a1, note="two words"'
    """
    if scheme is not None:
        need_str(scheme, "scheme")
    text, read = _render_params(scheme or "", "info", params)
    if not text:
        raise AuthError("Authentication-Info needs at least one auth-param")
    if scheme is not None:
        check(scheme, "info", None, read)
    return text
