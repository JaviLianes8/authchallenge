"""Parse WWW-Authenticate / Proxy-Authenticate and Authorization headers (RFC 7235)."""

from __future__ import annotations

import re

from ._grammar import TCHAR, is_token68, split_list, unquote
from ._model import Challenge, Credentials

_SCHEME = re.compile(rf"([{TCHAR}]+)(?:[ \t]+(.*))?$", re.DOTALL)
_PARAM = re.compile(rf'([{TCHAR}]+)[ \t]*=[ \t]*("(?:[^"\\]|\\.)*"|[{TCHAR}]+)', re.DOTALL)


def _parse_param(segment: str) -> tuple[str | None, str]:
    match = _PARAM.match(segment.strip())
    if match is None:
        return None, ""
    return match.group(1).lower(), unquote(match.group(2))


def _starts_challenge(segment: str) -> tuple[str, str] | None:
    """Return (scheme, remainder) if the segment opens a new challenge, else None.

    A leading token is a scheme unless it is immediately followed by "=", which makes
    the segment an auth-param that continues the current challenge.
    """
    match = _SCHEME.match(segment)
    if match is None:
        return None
    if segment[match.end(1) :].lstrip(" \t").startswith("="):
        return None
    rest = match.group(2)
    return match.group(1), rest.strip() if rest else ""


def parse_challenges(header: str) -> list[Challenge]:
    """Parse a WWW-Authenticate or Proxy-Authenticate header into its challenges."""
    challenges: list[Challenge] = []
    scheme: str | None = None
    token68: str | None = None
    params: dict[str, str] = {}

    def flush() -> None:
        nonlocal scheme, token68, params
        if scheme is not None:
            challenges.append(Challenge(scheme, token68, params))
        scheme, token68, params = None, None, {}

    for raw in split_list(header):
        segment = raw.strip()
        if not segment:
            continue
        start = _starts_challenge(segment)
        if start is not None:
            flush()
            scheme, rest = start
            if rest and is_token68(rest):
                token68 = rest
            elif rest:
                key, value = _parse_param(rest)
                if key is not None:
                    params[key] = value
        elif scheme is not None:
            key, value = _parse_param(segment)
            if key is not None:
                params[key] = value

    flush()
    return challenges


def parse_authorization(header: str) -> Credentials:
    """Parse a single Authorization or Proxy-Authorization credentials line."""
    text = header.strip()
    match = _SCHEME.match(text)
    if match is None:
        return Credentials("")
    scheme = match.group(1)
    rest = (match.group(2) or "").strip()
    if not rest:
        return Credentials(scheme)
    if is_token68(rest):
        return Credentials(scheme, token68=rest)
    params: dict[str, str] = {}
    for segment in split_list(rest):
        key, value = _parse_param(segment)
        if key is not None:
            params[key] = value
    return Credentials(scheme, params=params)
