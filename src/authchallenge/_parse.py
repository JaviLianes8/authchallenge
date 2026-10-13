"""Parse WWW-Authenticate, Authorization and Authentication-Info field values (RFC 9110)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from ._model import AuthError, Challenge, Credentials
from ._scan import Item, Param, classify, fail, prepare, split
from ._schemes import check


@dataclass
class _Draft:
    scheme: str
    offset: int
    token68: str | None
    open: bool
    params: list[Param] = field(default_factory=list)


def _items(value: str, strict: bool) -> list[Item]:
    text = prepare(value, strict)
    parts, open_quote = split(text)
    if strict and open_quote is not None:
        raise fail("unterminated quoted-string", open_quote)
    items = [classify(offset, raw, strict) for offset, raw in parts]
    if strict:
        for item in items:
            if item.error:
                raise fail(item.error, item.error_at)
    return items


def _add(params: list[Param], param: Param, strict: bool) -> None:
    if any(seen.name == param.name for seen in params):
        if strict:
            raise fail(f"duplicate auth-param {param.name!r}", param.offset)
        return  # the first one wins, as most user agents do
    params.append(param)


def _drafts(value: str, strict: bool) -> list[_Draft]:
    drafts: list[_Draft] = []
    for item in _items(value, strict):
        if item.kind == "challenge":
            drafts.append(_Draft(item.scheme, item.offset, item.token68, item.open))
            if item.param is not None:
                _add(drafts[-1].params, item.param, strict)
        elif item.kind == "param" and item.param is not None:
            current = drafts[-1] if drafts else None
            if current is None or current.token68 is not None or not current.open:
                if strict:
                    raise fail(f"auth-param {item.param.name!r} outside a challenge", item.offset)
                if current is None or current.token68 is not None:
                    continue
            current.open = True
            _add(current.params, item.param, strict)
    return drafts


def _checked(draft: _Draft, kind: str, strict: bool) -> _Draft:
    if strict:
        try:
            check(draft.scheme, kind, draft.token68, draft.params)
        except AuthError as error:
            raise AuthError(f"{error}, in the {kind} at offset {draft.offset}") from None
    return draft


def _lines(value: str | Iterable[str]) -> list[str]:
    return [value] if isinstance(value, str) else list(value)


def parse_challenges(value: str | Iterable[str], *, strict: bool = False) -> list[Challenge]:
    """Parse WWW-Authenticate or Proxy-Authenticate field values into their challenges.

    Pass one field value or an iterable of them (the field may occur several times).
    By default parsing is tolerant: malformed parts are skipped and the first of two
    params with the same name wins. With `strict=True` anything RFC 9110, RFC 7617,
    RFC 7616 or RFC 6750 forbids raises `AuthError` with the reason and offset.
    """
    challenges: list[Challenge] = []
    for line in _lines(value):
        for draft in _drafts(line, strict):
            _checked(draft, "challenge", strict)
            params = {param.name: param.value for param in draft.params}
            challenges.append(Challenge(draft.scheme, draft.token68, params))
    if strict and not challenges:
        raise AuthError("the field holds no challenge")
    return challenges


def parse_authorization(value: str, *, strict: bool = False) -> Credentials:
    """Parse an Authorization or Proxy-Authorization field value.

    Tolerant mode returns the first credentials found, or `Credentials("")` if none.
    Strict mode raises `AuthError` unless the value is exactly one valid credentials.
    """
    drafts = _drafts(value, strict)
    if strict:
        if not drafts or value.strip(" \t")[: len(drafts[0].scheme)] != drafts[0].scheme:
            raise AuthError("the field must start with an auth-scheme")
        if len(drafts) > 1:
            raise fail("only one credentials is allowed", drafts[1].offset)
        token68 = drafts[0].token68
        if token68 is not None and not value.rstrip(" \t").endswith(token68):
            raise AuthError("nothing may follow the token68 of credentials")
    if not drafts:
        return Credentials("")
    draft = _checked(drafts[0], "credentials", strict)
    params = {param.name: param.value for param in draft.params}
    return Credentials(draft.scheme, draft.token68, params)


def parse_auth_info(
    value: str | Iterable[str], *, strict: bool = False, scheme: str | None = None
) -> dict[str, str]:
    """Parse Authentication-Info or Proxy-Authentication-Info, a list of auth-params.

    Names are lower-cased and the first of two equal names wins. Strict mode refuses
    anything but auth-params and, given the `scheme` of the request's credentials,
    applies its rules (Digest: quoting, `nc`, and rspauth, cnonce and nc with qop).
    """
    params: list[Param] = []
    for line in _lines(value):
        for item in _items(line, strict):
            if item.kind == "param" and item.param is not None:
                _add(params, item.param, strict)
            elif item.kind != "empty" and strict:
                raise fail("expected an auth-param", item.offset)
    if strict and scheme is not None:
        try:
            check(scheme, "info", None, params)
        except AuthError as error:
            raise AuthError(f"{error}, in the {scheme} Authentication-Info") from None
    return {param.name: param.value for param in params}
