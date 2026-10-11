"""Parse and build HTTP auth challenge and credentials headers per RFC 7235."""

from __future__ import annotations

from ._build import build_authorization, build_challenge
from ._model import AuthError, Challenge, Credentials
from ._parse import parse_authorization, parse_challenges

__version__ = "0.1.0"

__all__ = [
    "AuthError",
    "Challenge",
    "Credentials",
    "build_authorization",
    "build_challenge",
    "parse_authorization",
    "parse_challenges",
]
