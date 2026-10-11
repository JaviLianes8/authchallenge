"""Typed result objects for parsed challenges and credentials."""

from __future__ import annotations

from dataclasses import dataclass, field


class AuthError(ValueError):
    """Raised when a header cannot be built from the given input."""


@dataclass(frozen=True)
class Challenge:
    """One authentication challenge: a scheme with either a token68 or auth-params."""

    scheme: str
    token68: str | None = None
    params: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Credentials:
    """Authorization credentials: a scheme with either a token68 or auth-params."""

    scheme: str
    token68: str | None = None
    params: dict[str, str] = field(default_factory=dict)
