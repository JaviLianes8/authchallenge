"""Parse and build HTTP authentication headers: challenges, credentials, Authentication-Info."""

from __future__ import annotations

from ._basic import decode_basic, encode_basic
from ._build import build_auth_info, build_authorization, build_challenge
from ._extvalue import decode_ext_value, encode_ext_value
from ._helpers import build_bearer_challenge, select_challenge
from ._model import AuthError, Challenge, Credentials
from ._parse import parse_auth_info, parse_authorization, parse_challenges

__version__ = "0.2.0"

__all__ = [
    "AuthError",
    "Challenge",
    "Credentials",
    "build_auth_info",
    "build_authorization",
    "build_bearer_challenge",
    "build_challenge",
    "decode_basic",
    "decode_ext_value",
    "encode_basic",
    "encode_ext_value",
    "parse_auth_info",
    "parse_authorization",
    "parse_challenges",
    "select_challenge",
]
