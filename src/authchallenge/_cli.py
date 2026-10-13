"""Command line: print parsed authentication fields as JSON, or lint them with --strict."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from typing import Any

from ._model import AuthError, Challenge, Credentials
from ._parse import parse_auth_info, parse_authorization, parse_challenges

_KINDS = {
    "www-authenticate": "challenges",
    "proxy-authenticate": "challenges",
    "authorization": "credentials",
    "proxy-authorization": "credentials",
    "authentication-info": "info",
    "proxy-authentication-info": "info",
}
_FIELD_LINE = re.compile(r"([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*(.*)")


def _fields(text: str, default: str) -> list[tuple[str, str]]:
    """Return (field name, value) pairs from a header dump, or one per plain line."""
    lines = [line.rstrip("\r") for line in text.splitlines()]
    dump = any(line.startswith("HTTP/") or _FIELD_LINE.fullmatch(line) for line in lines)
    if not dump:
        return [(default, line.strip()) for line in lines if line.strip()]
    pairs: list[tuple[str, str]] = []
    for line in lines:
        match = _FIELD_LINE.fullmatch(line)
        if match is not None:
            pairs.append((match.group(1), match.group(2)))
        elif line[:1] in (" ", "\t") and pairs:
            pairs[-1] = (pairs[-1][0], pairs[-1][1] + "\r\n" + line)
    return [(name, value) for name, value in pairs if name.lower() in _KINDS]


def _plain(found: Challenge | Credentials) -> dict[str, Any]:
    return {"scheme": found.scheme, "token68": found.token68, "params": found.params}


def _report(name: str, value: str, strict: bool) -> dict[str, Any]:
    kind = _KINDS[name.lower()]
    entry: dict[str, Any] = {"field": name}
    try:
        if kind == "challenges":
            entry[kind] = [_plain(c) for c in parse_challenges(value, strict=strict)]
        elif kind == "credentials":
            entry[kind] = _plain(parse_authorization(value, strict=strict))
        else:
            entry[kind] = parse_auth_info(value, strict=strict)
    except AuthError as error:
        entry["error"] = str(error)
    return entry


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line; return 0, or 1 when strict mode found a problem."""
    parser = argparse.ArgumentParser(
        prog="authchallenge",
        description="Parse WWW-Authenticate, Authorization and Authentication-Info values. "
        "Values come as arguments or one per stdin line; a header dump such as "
        "`curl -sI` output is also read from stdin.",
    )
    parser.add_argument("values", nargs="*", help="field values (default: read stdin)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--authorization", action="store_true", help="values are credentials")
    group.add_argument("--info", action="store_true", help="values are Authentication-Info")
    parser.add_argument("--strict", action="store_true", help="report every rule broken")
    args = parser.parse_args(argv)
    default = "WWW-Authenticate"
    if args.authorization or args.info:
        default = "Authorization" if args.authorization else "Authentication-Info"
    if args.values:
        fields = [(default, value) for value in args.values]
    else:
        fields = _fields(sys.stdin.read(), default)
    if not fields:
        parser.error("no field values given")
    report = [_report(name, value, args.strict) for name, value in fields]
    print(json.dumps(report, indent=2))
    errors = [entry for entry in report if "error" in entry]
    for entry in errors:
        print(f"authchallenge: strict: {entry['field']}: {entry['error']}", file=sys.stderr)
    return 1 if errors else 0
