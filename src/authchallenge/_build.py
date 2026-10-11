"""Build WWW-Authenticate challenge and Authorization credentials strings (RFC 7235)."""

from __future__ import annotations

from collections.abc import Mapping

from ._grammar import is_token, is_token68, quote_if_needed
from ._model import AuthError


def _render(scheme: str, params: Mapping[str, str] | None, token68: str | None) -> str:
    if not is_token(scheme):
        raise AuthError(f"invalid auth-scheme: {scheme!r}")
    if token68 is not None and params:
        raise AuthError("use either token68 or params, not both")
    if token68 is not None:
        if not is_token68(token68):
            raise AuthError(f"invalid token68: {token68!r}")
        return f"{scheme} {token68}"
    if params:
        rendered = []
        for key, value in params.items():
            if not is_token(key):
                raise AuthError(f"invalid auth-param name: {key!r}")
            rendered.append(f"{key}={quote_if_needed(value)}")
        return f"{scheme} " + ", ".join(rendered)
    return scheme


def build_challenge(
    scheme: str,
    params: Mapping[str, str] | None = None,
    token68: str | None = None,
) -> str:
    """Build one challenge for a WWW-Authenticate or Proxy-Authenticate header."""
    return _render(scheme, params, token68)


def build_authorization(
    scheme: str,
    params: Mapping[str, str] | None = None,
    token68: str | None = None,
) -> str:
    """Build an Authorization or Proxy-Authorization credentials line."""
    return _render(scheme, params, token68)
