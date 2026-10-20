"""Parse WWW-Authenticate, Authorization and Authentication-Info field values (RFC 9110)."""

from __future__ import annotations

from collections.abc import Iterable

from ._drafts import add_param, checked, each_line, line_items, read_drafts
from ._grammar import need_str, shown
from ._model import AuthError, Challenge, Credentials
from ._scan import Param, fail
from ._schemes import check


def parse_challenges(value: str | Iterable[str], *, strict: bool = False) -> list[Challenge]:
    """Parse WWW-Authenticate or Proxy-Authenticate field values into their challenges.

    Pass one field value or an iterable of them (the field may occur several times).
    By default parsing is tolerant: malformed parts are skipped and the first of two
    params with the same name wins. With `strict=True` anything RFC 9110, RFC 7617,
    RFC 7616 or RFC 6750 forbids raises `AuthError` with the reason and offset.
    Field values are `str` (decode received bytes as latin-1); other types raise
    `TypeError`.

    >>> from authchallenge import parse_challenges
    >>> for challenge in parse_challenges('Basic realm="simple", Newauth realm="apps", type=1'):
    ...     print(challenge.scheme, challenge.params)
    Basic {'realm': 'simple'}
    Newauth {'realm': 'apps', 'type': '1'}
    >>> parse_challenges(["Negotiate a87421bff012e83c==", "Basic realm=a"])[0].token68
    'a87421bff012e83c=='
    """

    def read(line: str) -> list[Challenge]:
        drafts = [checked(d, "challenge", strict) for d in read_drafts(line, strict)]
        return [Challenge(d.scheme, d.token68, d.values()) for d in drafts]

    challenges = [c for found in each_line(value, read) for c in found]
    if strict and not challenges:
        raise AuthError("the field holds no challenge")
    return challenges


def parse_authorization(value: str, *, strict: bool = False) -> Credentials:
    """Parse an Authorization or Proxy-Authorization field value.

    Tolerant mode returns the first credentials found, or `Credentials("")` if none.
    Strict mode raises `AuthError` unless the value is exactly one valid credentials.

    >>> from authchallenge import parse_authorization
    >>> creds = parse_authorization('Digest username="Mufasa", realm="a", nc=00000001')
    >>> creds.scheme, creds.params["username"], creds.params["nc"]
    ('Digest', 'Mufasa', '00000001')
    >>> parse_authorization("Bearer mF_9.B5f-4.1JqM").token68
    'mF_9.B5f-4.1JqM'
    """
    drafts = read_drafts(need_str(value, "the Authorization value"), strict, "credentials")
    if strict:
        if not drafts or value.strip(" \t")[: len(drafts[0].scheme)] != drafts[0].scheme:
            raise AuthError("the field must start with an auth-scheme")
        scheme_end = drafts[0].offset + len(drafts[0].scheme)
        if value.rstrip(" \t")[scheme_end : scheme_end + 1] not in ("", " "):
            # Credentials are one element, not a list: "Basic," is not allowed.
            raise fail("expected a space after the auth-scheme", scheme_end)
        if len(drafts) > 1:
            raise fail("only one credentials is allowed", drafts[1].offset)
        token68 = drafts[0].token68
        if token68 is not None and not value.rstrip(" \t").endswith(token68):
            raise AuthError("nothing may follow the token68 of credentials")
    if not drafts:
        return Credentials("")
    draft = checked(drafts[0], "credentials", strict)
    return Credentials(draft.scheme, draft.token68, draft.values())


def parse_auth_info(
    value: str | Iterable[str], *, strict: bool = False, scheme: str | None = None
) -> dict[str, str]:
    """Parse Authentication-Info or Proxy-Authentication-Info, a list of auth-params.

    Names are lower-cased and the first of two equal names wins. Strict mode refuses
    anything but auth-params and, given the `scheme` of the request's credentials,
    applies its rules (Digest: quoting, `nc`, and rspauth, cnonce and nc with qop).

    >>> from authchallenge import parse_auth_info
    >>> parse_auth_info('NextNonce="47364c23", qop=auth, nc=00000001')
    {'nextnonce': '47364c23', 'qop': 'auth', 'nc': '00000001'}
    """
    if scheme is not None:
        need_str(scheme, "scheme")
    params: dict[str, Param] = {}

    def read(line: str) -> None:
        for items in line_items(line, strict):
            for item in items:
                if item.kind == "param" and item.param is not None:
                    add_param(params, item.param, strict)
                elif item.kind != "empty" and strict:
                    raise fail("expected an auth-param", item.offset)

    each_line(value, read)
    if strict and scheme is not None:
        try:
            check(scheme, "info", None, list(params.values()))
        except AuthError as error:
            raise AuthError(f"{error}, in the {shown(scheme)} Authentication-Info") from None
    return {name: param.value for name, param in params.items()}
