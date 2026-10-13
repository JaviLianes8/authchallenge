"""Check the library against RFC 9110, RFC 7617, RFC 7616 and RFC 6750 as fetched.

The files are read from tests/upstream (URL, size and sha256 in MANIFEST.json); these
tests skip until `python scripts/fetch_upstream.py` has fetched them.
"""

from __future__ import annotations

import re

import pytest
from conftest import field_lines, section

from authchallenge import (
    AuthError,
    build_authorization,
    build_bearer_challenge,
    build_challenge,
    decode_basic,
    decode_ext_value,
    encode_basic,
    parse_authorization,
    parse_challenges,
)
from authchallenge._grammar import TCHAR, TOKEN68_CHARS, is_field_text
from authchallenge._schemes import _NQSCHAR, _SCOPE_TOKEN, _URI_CHARS, DIGEST_BARE, DIGEST_QUOTED

ALPHA_DIGIT = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")


def _rule(text: str, name: str) -> str:
    match = re.search(rf"^ +{re.escape(name)} += (.+?)\n\n", text, re.MULTILINE | re.DOTALL)
    assert match is not None, name
    return match.group(1)


def _abnf_codes(rule: str) -> set[int]:
    codes: set[int] = set()
    for low, high in re.findall(r"%x([0-9A-Fa-f]+)(?:-([0-9A-Fa-f]+))?", rule):
        codes |= set(range(int(low, 16), int(high or low, 16) + 1))
    return codes


def test_tchar_matches_section_5_6_2(rfc9110: str) -> None:
    rule = _rule(rfc9110, "tchar")
    assert set(re.findall(r'"(.)"', rule)) | ALPHA_DIGIT == set(TCHAR)


def test_token68_matches_section_11_2(rfc9110: str) -> None:
    rule = _rule(rfc9110, "token68")
    assert rule.rstrip().endswith('*"="')
    assert set(re.findall(r'"(.)"', rule)) - {"="} | ALPHA_DIGIT == set(TOKEN68_CHARS)


def test_builder_text_is_what_section_5_5_asks_of_new_fields(rfc9110: str) -> None:
    assert re.search(r"visible\s+US-ASCII octets \(VCHAR\), SP, and HTAB", rfc9110)
    allowed = {code for code in range(0x110) if is_field_text(chr(code))}
    assert allowed == {0x09, *range(0x20, 0x7F)}


def test_the_example_of_section_11_6_1(rfc9110: str) -> None:
    (value,) = field_lines(
        section(rfc9110, "11.6.1.  WWW-Authenticate", "11.6.2."), "WWW-Authenticate"
    )
    basic, newauth = parse_challenges(value, strict=True)
    assert (basic.scheme, basic.params) == ("Basic", {"realm": "simple"})
    assert newauth.params == {"realm": "apps", "type": "1", "title": 'Login to "apps"'}


def test_param_names_are_unique_per_section_11_2(rfc9110: str) -> None:
    assert re.search(r"each parameter name MUST only occur\s+once per challenge", rfc9110)
    with pytest.raises(AuthError, match="duplicate"):
        parse_challenges('Newauth a=1, A="2"', strict=True)


def test_basic_vectors_of_rfc_7617(rfc7617: str) -> None:
    aladdin, pound = field_lines(rfc7617, "Authorization")
    assert re.search(r'user-id "Aladdin" and password\s+"open sesame"', rfc7617)
    assert encode_basic("Aladdin", "open sesame") == aladdin
    assert decode_basic(aladdin) == ("Aladdin", "open sesame")
    # Section 2.1: user "test", password "123" and U+00A3, in UTF-8.
    assert 'The user\'s name is "test", and the password is the string "123"' in rfc7617
    assert encode_basic("test", "123£") == pound
    assert decode_basic(parse_authorization(pound, strict=True)) == ("test", "123£")


def test_basic_challenges_of_rfc_7617(rfc7617: str) -> None:
    for value in field_lines(rfc7617, "WWW-Authenticate"):
        (challenge,) = parse_challenges(value, strict=True)
        assert build_challenge(challenge.scheme, challenge.params) == value
    assert re.search(r"The only allowed value is \"UTF-8\"", rfc7617)
    with pytest.raises(AuthError, match="charset"):
        build_challenge("Basic", {"realm": "foo", "charset": "latin1"})


@pytest.mark.parametrize(
    ("heading", "end", "kind"),
    [
        ("3.3.  The WWW-Authenticate", "3.4.  ", "challenge"),
        ("3.4.  The Authorization", "3.4.1.", "credentials"),
        ("3.5.  The Authentication-Info", "3.6.  ", "info"),
    ],
)
def test_digest_quoting_lists_of_rfc_7616(rfc7616: str, heading: str, end: str, kind: str) -> None:
    text = section(rfc7616, heading, end)
    lists = re.findall(
        r"MUST (only|NOT) generate the quoted string\s+syntax(?: values)? for the following"
        r"\s+parameters:\s+([^.]+)\.",
        text,
    )
    found = {how: set(re.split(r",\s*(?:and\s+)?|\s+and\s+", names)) for how, names in lists}
    assert found == {"only": set(DIGEST_QUOTED[kind]), "NOT": set(DIGEST_BARE[kind])}


def test_digest_examples_of_rfc_7616(rfc7616: str) -> None:
    first = section(rfc7616, "3.9.1.  Example", "3.9.2.")
    second = section(rfc7616, "3.9.2.  Example", "4.  ")
    challenges = field_lines(first, "WWW-Authenticate") + field_lines(second, "WWW-Authenticate")
    credentials = field_lines(first, "Authorization") + field_lines(second, "Authorization")
    assert (len(challenges), len(credentials)) == (3, 4)
    sha256, md5 = parse_challenges(challenges[:2], strict=True)
    assert (sha256.params["algorithm"], md5.params["algorithm"]) == ("SHA-256", "MD5")
    for value in challenges:
        (challenge,) = parse_challenges(value, strict=True)
        assert build_challenge(challenge.scheme, challenge.params) == value
    for value in credentials:
        parsed = parse_authorization(value, strict=True)
        assert build_authorization(parsed.scheme, parsed.params) == value
    # The username of section 3.9.2, written out in the text before the example.
    hashed = parse_authorization(credentials[-1], strict=True)
    assert decode_ext_value(hashed.params["username*"]) == "Jäsøn Doe"


def test_bearer_character_sets_of_rfc_6750(rfc6750: str) -> None:
    text = section(rfc6750, "3.  The WWW-Authenticate", "3.1.")
    scope = re.search(
        r'Values for the "scope".*?outside the set (.+?) for representing', text, re.S
    )
    error = re.search(r'Values for the "error" and.*?outside the set (.+?)\.', text, re.S)
    uri = re.search(r'Values for the "error_uri".*?outside the set (.+?)\.', text, re.S)
    assert scope is not None and error is not None and uri is not None
    for rule, pattern in ((scope, _SCOPE_TOKEN), (error, _NQSCHAR), (uri, _URI_CHARS)):
        expected = _abnf_codes(rule.group(1))
        assert {c for c in range(0x100) if pattern.fullmatch(chr(c))} == expected


def test_bearer_examples_and_error_codes_of_rfc_6750(rfc6750: str) -> None:
    short, expired = field_lines(
        section(rfc6750, "3.  The WWW-Authenticate", "3.1."), "WWW-Authenticate"
    )
    assert build_bearer_challenge(realm="example") == short
    built = build_bearer_challenge(
        realm="example", error="invalid_token", error_description="The access token expired"
    )
    assert built == expired
    assert parse_challenges(expired, strict=True)[0].params["error"] == "invalid_token"
    codes = re.findall(r"^   ([a-z_]+)\n", section(rfc6750, "3.1.  Error Codes", "4.  "), re.M)
    assert codes == ["invalid_request", "invalid_token", "insufficient_scope"]
    for code in codes:
        parse_challenges(build_bearer_challenge(error=code), strict=True)
