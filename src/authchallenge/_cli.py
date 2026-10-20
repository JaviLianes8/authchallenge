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
    """Return (field name, value) pairs from a header dump, or one per plain line.

    The first non-empty line decides: a status line or a `Name: value` line makes the
    whole input a header dump, of which only the authentication fields are read. Only
    LF ends a line (with an optional CR before it), as in HTTP/1.1.
    """
    lines = [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]
    first = next((line for line in lines if line.strip(" \t")), "")
    dump = first.startswith("HTTP/") or _FIELD_LINE.fullmatch(first) is not None
    if not dump:
        return [(default, line.strip(" \t")) for line in lines if line.strip(" \t")]
    fields: list[tuple[str, list[str]]] = []
    for line in lines:
        match = _FIELD_LINE.fullmatch(line)
        if match is not None:
            fields.append((match.group(1), [match.group(2)]))
        elif line[:1] in (" ", "\t") and fields:
            fields[-1][1].append(line)  # obs-fold, joined once below
    return [(name, "\r\n".join(parts)) for name, parts in fields if name.lower() in _KINDS]


def _stdin() -> str:
    """Read stdin as octets decoded as latin-1, the way field values are received."""
    buffer = getattr(sys.stdin, "buffer", None)
    if buffer is None:  # a text stream without octets underneath, such as io.StringIO
        return sys.stdin.read()
    data: bytes = buffer.read()
    return data.decode("latin-1")


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
    parser.add_argument("--strict", action="store_true", help="exit 1 on the first broken rule")
    args = parser.parse_args(argv)
    default = "WWW-Authenticate"
    if args.authorization or args.info:
        default = "Authorization" if args.authorization else "Authentication-Info"
    if args.values:
        fields = [(default, value) for value in args.values]
    else:
        fields = _fields(_stdin(), default)
    if not fields:
        parser.error("no field values given")
    report = [_report(name, value, args.strict) for name, value in fields]
    print(json.dumps(report, indent=2))
    errors = [entry for entry in report if "error" in entry]
    for entry in errors:
        print(f"authchallenge: strict: {entry['field']}: {entry['error']}", file=sys.stderr)
    return 1 if errors else 0
