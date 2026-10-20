"""Typed result objects for parsed challenges and credentials."""

from __future__ import annotations

from dataclasses import dataclass, field


class AuthError(ValueError):
    """Raised when a header cannot be built, or fails strict parsing, with the reason.

    It is a `ValueError`. Messages name the broken rule and, for strict parsing, the
    offset; they quote at most 40 characters of the input and never a token68, which
    often carries a password or a bearer token. Arguments of the wrong type raise
    `TypeError` instead.

    >>> from authchallenge import AuthError, parse_challenges
    >>> try:
    ...     parse_challenges("Basic realm=a", strict=True)
    ... except AuthError as error:
    ...     print(error)
    the realm parameter must be a quoted-string, in the challenge at offset 0
    """


@dataclass(frozen=True)
class Challenge:
    """One authentication challenge: a scheme with either a token68 or auth-params.

    The scheme keeps the case it was written in (compare it case-insensitively); param
    names are lower-cased, and values have their quoting removed. Instances compare by
    value; they are not hashable, because `params` is a dict.

    >>> from authchallenge import Challenge
    >>> Challenge("Basic", params={"realm": "api"})
    Challenge(scheme='Basic', token68=None, params={'realm': 'api'})
    """

    scheme: str
    token68: str | None = None
    params: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Credentials:
    """Authorization credentials: a scheme with either a token68 or auth-params.

    The token68 of Basic and Bearer credentials is a secret, so `repr` hides it; read it
    from the `token68` attribute. Instances compare by value and are not hashable.

    >>> from authchallenge import Credentials
    >>> creds = Credentials("Bearer", "mF_9.B5f-4.1JqM")
    >>> creds
    Credentials(scheme='Bearer', token68=<hidden>, params={})
    >>> creds.token68
    'mF_9.B5f-4.1JqM'
    """

    scheme: str
    token68: str | None = None
    params: dict[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        token = "None" if self.token68 is None else "<hidden>"
        return f"Credentials(scheme={self.scheme!r}, token68={token}, params={self.params!r})"
