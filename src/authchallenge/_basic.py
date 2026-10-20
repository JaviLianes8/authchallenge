"""Basic credentials (RFC 7617): user-pass encoding and decoding."""

from __future__ import annotations

import base64
import binascii
import codecs

from ._grammar import is_token68, need_str, shown
from ._model import AuthError, Credentials


def _has_control(text: str) -> bool:
    # RFC 7617 refers to CTL of RFC 5234: the ASCII controls and DEL (see erratum 9174).
    return any(ord(char) < 0x20 or ord(char) == 0x7F for char in text)


def _codec(charset: str) -> str:
    # RFC 7617 needs an encoding that maps US-ASCII to single octets: UTF-8 or ISO-8859-1.
    try:
        name = codecs.lookup(need_str(charset, "charset")).name
    except LookupError:
        name = ""
    if name not in ("utf-8", "iso8859-1"):
        raise AuthError(f"unsupported Basic charset {shown(charset)}: use 'utf-8' or 'latin-1'")
    return name


def split_user_pass(token68: str, charset: str) -> tuple[str, str]:
    """Decode a Basic token68 into (user-id, password), raising AuthError when malformed."""
    # The token68 carries the password: no message ever quotes it.
    if not is_token68(token68):
        raise AuthError("invalid token68: Basic credentials are base64 after the scheme")
    try:
        raw = base64.b64decode(token68, validate=True)
    except (binascii.Error, ValueError) as error:
        raise AuthError("Basic credentials are not valid base64") from error
    try:
        text = raw.decode(_codec(charset))
    except UnicodeDecodeError as error:
        raise AuthError(f"Basic credentials are not valid {charset}") from error
    user_id, colon, password = text.partition(":")
    if not colon:
        raise AuthError("Basic credentials lack the ':' between user-id and password")
    if _has_control(text):
        raise AuthError("Basic user-id and password must not contain control characters")
    return user_id, password


def encode_basic(user_id: str, password: str, *, charset: str = "utf-8") -> str:
    """Build `Basic <base64>` credentials for an Authorization header (RFC 7617).

    The user-id may not contain a colon, and neither part may contain control characters.
    UTF-8 is what a server asks for with `charset="UTF-8"`; pass "latin-1" for servers
    that expect ISO-8859-1; other charsets raise AuthError. The text is encoded as
    given, without Unicode normalisation.

    >>> from authchallenge import encode_basic
    >>> encode_basic("Aladdin", "open sesame")
    'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=='
    >>> encode_basic("test", "123£", charset="latin-1")
    'Basic dGVzdDoxMjOj'
    """
    need_str(user_id, "user_id")
    need_str(password, "password")
    if ":" in user_id:
        raise AuthError("a Basic user-id cannot contain ':'")
    if _has_control(user_id) or _has_control(password):
        raise AuthError("Basic user-id and password must not contain control characters")
    try:
        raw = f"{user_id}:{password}".encode(_codec(charset))
    except UnicodeEncodeError as error:
        raise AuthError(f"the credentials cannot be encoded as {charset}") from error
    return "Basic " + base64.b64encode(raw).decode("ascii")


def decode_basic(credentials: str | Credentials, *, charset: str = "utf-8") -> tuple[str, str]:
    """Return (user-id, password) from Basic credentials, raising AuthError if malformed.

    Accepts the Authorization field value (`Basic QWxh...`) or a parsed `Credentials`.
    The text after the first colon is the password, as RFC 7617 section 2 says.
    Error messages never quote the base64 text, which carries the password.

    >>> from authchallenge import decode_basic, parse_authorization
    >>> decode_basic("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
    ('Aladdin', 'open sesame')
    >>> decode_basic(parse_authorization("Basic dGVzdDoxMjPCow=="))
    ('test', '123£')
    """
    if isinstance(credentials, str):
        scheme, space, token68 = credentials.strip(" \t").replace("\t", " ").partition(" ")
        token68 = token68.strip(" ")
        if not space and scheme.lower() != "basic":
            # Without a space the text may be a bare token68, so it is never quoted.
            raise AuthError("not Basic credentials: the value lacks the 'Basic' scheme")
    elif isinstance(credentials, Credentials):
        scheme, token68 = need_str(credentials.scheme, "scheme"), credentials.token68 or ""
    else:
        raise TypeError(f"expected a str or Credentials, not {type(credentials).__name__}")
    if scheme.lower() != "basic":
        raise AuthError(f"not Basic credentials: {shown(scheme)}")
    return split_user_pass(token68, charset)
