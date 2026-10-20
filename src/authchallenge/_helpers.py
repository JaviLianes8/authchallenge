"""Conveniences on top of the codec: Bearer challenges and challenge selection."""

from __future__ import annotations

from collections.abc import Iterable

from ._build import build_challenge
from ._grammar import need_str
from ._model import AuthError, Challenge


def build_bearer_challenge(
    *,
    realm: str | None = None,
    scope: str | Iterable[str] | None = None,
    error: str | None = None,
    error_description: str | None = None,
    error_uri: str | None = None,
) -> str:
    """Build a Bearer challenge (RFC 6750 section 3) with its attributes quoted.

    `scope` is a space-delimited string or an iterable of scope tokens. Each attribute is
    checked against the character set RFC 6750 allows; `error` is usually one of
    invalid_request, invalid_token or insufficient_scope (section 3.1). At least one
    attribute is required.

    >>> from authchallenge import build_bearer_challenge
    >>> build_bearer_challenge(realm="example", error="invalid_token", scope=["read", "write"])
    'Bearer realm="example", scope="read write", error="invalid_token"'
    """
    if scope is not None and not isinstance(scope, str):
        try:
            tokens = list(scope)
        except TypeError:
            raise TypeError(
                f"scope must be a str or an iterable of str, not {type(scope).__name__}"
            ) from None
        if not tokens or not all(need_str(t, "each scope token") and " " not in t for t in tokens):
            raise AuthError("scope tokens are non-empty strings without spaces")
        scope = " ".join(tokens)
    attributes = {
        "realm": realm,
        "scope": scope,
        "error": error,
        "error_description": error_description,
        "error_uri": error_uri,
    }
    params = {name: value for name, value in attributes.items() if value is not None}
    return build_challenge("Bearer", params)


def select_challenge(challenges: Iterable[Challenge], *schemes: str) -> Challenge | None:
    """Return the first challenge of the most preferred scheme, or None.

    `schemes` lists the schemes the caller supports, best first; they are compared
    case-insensitively, as RFC 9110 section 11.1 requires.

    >>> from authchallenge import parse_challenges, select_challenge
    >>> offered = parse_challenges('Basic realm="a", Bearer realm="b", Negotiate')
    >>> select_challenge(offered, "negotiate", "bearer").scheme
    'Negotiate'
    >>> select_challenge(offered, "digest") is None
    True
    """
    try:
        offered = list(challenges)
    except TypeError:
        raise TypeError(
            f"challenges must be an iterable of Challenge, not {type(challenges).__name__}"
        ) from None
    for challenge in offered:
        if not isinstance(challenge, Challenge):
            raise TypeError(f"expected Challenge objects, not {type(challenge).__name__}")
        need_str(challenge.scheme, "the scheme of each challenge")
    for wanted in schemes:
        need_str(wanted, "each scheme")
        for challenge in offered:
            if challenge.scheme.lower() == wanted.lower():
                return challenge
    return None
