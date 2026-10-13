"""Tolerant parsing: what is kept, what is skipped, and how ambiguities are resolved."""

from __future__ import annotations

import pytest

from authchallenge import Challenge, parse_auth_info, parse_authorization, parse_challenges


def test_the_first_of_two_equal_params_wins() -> None:
    (challenge,) = parse_challenges('Basic realm="foo", REALM="bar"')
    assert challenge.params == {"realm": "foo"}


@pytest.mark.parametrize(
    "folded", ['Basic\r\n realm="foo"', 'Basic\n\trealm="foo"', 'Basic realm="foo",\r\n x=1']
)
def test_obsolete_line_folding_is_read_as_a_space(folded: str) -> None:
    (challenge,) = parse_challenges(folded)
    assert challenge.params["realm"] == "foo"


def test_several_field_lines_are_one_list() -> None:
    lines = ['Newauth realm="a"', "", 'Basic realm="b"']
    assert [c.scheme for c in parse_challenges(lines)] == ["Newauth", "Basic"]
    assert [c.scheme for c in parse_challenges(iter(lines))] == ["Newauth", "Basic"]


def test_an_open_quote_does_not_swallow_the_next_field_line() -> None:
    challenges = parse_challenges(['Newauth realm="a', 'Basic realm="b"'])
    assert challenges == [Challenge("Newauth"), Challenge("Basic", None, {"realm": "b"})]


def test_a_token68_challenge_collects_no_params() -> None:
    first, second = parse_challenges('Newauth abc=, x=y, Basic realm="r"')
    assert first == Challenge("Newauth", "abc=")
    assert second.params == {"realm": "r"}


def test_token68_versus_auth_param() -> None:
    assert parse_challenges("X a=")[0].token68 == "a="
    assert parse_challenges("X a= b")[0].params == {"a": "b"}
    assert parse_challenges("X realm")[0].token68 == "realm"
    assert parse_challenges("X a==b")[0] == Challenge("X")


def test_a_param_after_a_bare_scheme_and_comma_is_attached() -> None:
    (challenge,) = parse_challenges('Basic, realm="foo"')
    assert challenge.params == {"realm": "foo"}


def test_a_tab_after_the_scheme_is_accepted() -> None:
    assert parse_challenges('Basic\trealm="x"')[0].params == {"realm": "x"}


def test_empty_list_elements_are_skipped() -> None:
    (challenge,) = parse_challenges(', , Basic , realm="x",, a=b,,')
    assert challenge.params == {"realm": "x", "a": "b"}


def test_junk_is_skipped_and_the_rest_kept() -> None:
    challenges = parse_challenges('Basic realm="x" extra, =junk, Bearer error=e')
    assert [(c.scheme, c.params) for c in challenges] == [
        ("Basic", {"realm": "x"}),
        ("Bearer", {"error": "e"}),
    ]


def test_a_param_before_any_challenge_is_dropped() -> None:
    assert parse_challenges('realm="x", Basic') == [Challenge("Basic")]


def test_an_unterminated_quote_drops_the_param_but_keeps_the_scheme() -> None:
    assert parse_challenges('Basic realm="basic') == [Challenge("Basic")]


def test_quoted_pairs_are_resolved() -> None:
    (challenge,) = parse_challenges(r'Basic realm="\f\o\o", x="\"q\""')
    assert challenge.params == {"realm": "foo", "x": '"q"'}


def test_a_comma_inside_quotes_does_not_split() -> None:
    (challenge,) = parse_challenges('Digest qop="auth, auth-int", realm="a,b"')
    assert challenge.params == {"qop": "auth, auth-int", "realm": "a,b"}


def test_scheme_case_is_kept() -> None:
    assert parse_challenges('bAsIc realm="x"')[0].scheme == "bAsIc"


def test_authorization_takes_the_first_credentials() -> None:
    creds = parse_authorization('Digest a="b", Basic x')
    assert (creds.scheme, creds.params) == ("Digest", {"a": "b"})


def test_authorization_unfolds_and_tolerates_junk() -> None:
    assert parse_authorization("Basic\r\n QQ==").token68 == "QQ=="
    assert parse_authorization("basic QQ== extra").token68 is None


def test_auth_info_reads_params_and_skips_the_rest() -> None:
    info = parse_auth_info(['nextnonce="a", qop=auth', "junk, NC=00000001, nc=2"])
    assert info == {"nextnonce": "a", "qop": "auth", "nc": "00000001"}
