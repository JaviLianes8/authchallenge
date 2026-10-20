# authchallenge 1.0.0 author mutation round

Part of item 18 of the certification, see
[CERT-1.0-REPORT.md](https://github.com/JaviLianes8/authchallenge/blob/main/CERT-1.0-REPORT.md).
Each mutant was applied alone to a fresh clone of `release/1.0.0` at 5ec0b2b on another
machine (CPython 3.14.2), and the whole suite was run with `-x`, a 300 s limit per test,
the fetched sources, httpx, requests, werkzeug and the 0.2.0 oracle present. The column
"caught by" names the first test that failed.

| Id | Module | Mutation | Result | Caught by |
| --- | --- | --- | --- | --- |
| M01 | `_grammar.py` | tchar loses '!' | killed | `tests/test_sources.py::test_tchar_matches_section_5_6_2` |
| M02 | `_grammar.py` | builders let DEL through | killed | `tests/test_build.py::test_values_that_could_break_the_header_are_refused[a\x7fb]` |
| M03 | `_grammar.py` | strict accepts U+0100 | killed | `tests/test_strict.py::test_strict_reasons[Basic` |
| M04 | `_grammar.py` | quote stops escaping backslash | killed | `tests/test_build.py::test_build_escapes_quotes_and_backslashes_in_values` |
| M05 | `_grammar.py` | empty quoted-string kept with quotes | killed | `tests/test_fuzz.py::test_built_headers_read_back_strictly_to_the_same_values[1]` |
| M06 | `_scan.py` | bare LF fold not unfolded | killed | `tests/test_tolerant.py::test_obsolete_line_folding_is_read_as_a_space[Basic\n\trealm="foo"]` |
| M07 | `_scan.py` | backslash escapes outside quotes | killed | `tests/test_contract_edges.py::test_a_backslash_outside_a_quoted_string_escapes_nothing` |
| M08 | `_scan.py` | a scheme without a space takes params | killed | `tests/test_docs.py::test_every_readme_example_runs_and_prints_its_comments` |
| M09 | `_drafts.py` | last duplicate wins | killed | `tests/test_docs.py::test_every_readme_example_runs_and_prints_its_comments` |
| M10 | `_parse.py` | strict credentials accept a comma after the scheme | killed | `tests/test_fuzz.py::test_strict_credentials_and_info_accept_exactly_the_grammar[1]` |
| M11 | `_parse.py` | two credentials accepted | killed | `tests/test_fuzz.py::test_strict_credentials_and_info_accept_exactly_the_grammar[1]` |
| M12 | `_schemes.py` | Digest stale may be quoted | killed | `tests/test_schemes.py::test_challenge_rules[Digest` |
| M13 | `_schemes.py` | nc of 7 digits accepted | killed | `tests/test_contract_edges.py::test_digest_nc_is_exactly_eight_hex_digits[0000001]` |
| M14 | `_schemes.py` | scope allows a double quote | killed | `tests/test_sources.py::test_bearer_character_sets_of_rfc_6750` |
| M15 | `_basic.py` | Basic allows U+001F | killed | `tests/test_contract_edges.py::test_basic_refuses_every_ascii_control[\x1f]` |
| M16 | `_basic.py` | password split at the last colon | killed | `tests/test_docs.py::test_every_guide_example_runs_and_prints_its_comments` |
| M17 | `_basic.py` | Basic accepts ascii | killed | `tests/test_contract_edges.py::test_basic_charsets_are_utf_8_and_latin_1_only[ascii]` |
| M18 | `_extvalue.py` | ISO-8859-1 ext-values refused | killed | `src/authchallenge/_extvalue.py::authchallenge._extvalue.decode_ext_value` |
| M19 | `_extvalue.py` | ext-value lets DEL through | killed | `tests/test_review_fixes.py::test_ext_values_that_decode_to_controls_are_refused[UTF-8''%7F]` |
| M20 | `_extvalue.py` | '\|' percent-encoded | killed | `tests/test_spec_rfc8187.py::test_encoding_leaves_exactly_attr_char_unescaped` |
| M21 | `_grammar.py` | messages quote 400 characters | killed | `tests/test_contract_api.py::test_messages_quote_at_most_forty_characters_of_input[<lambda>0]` |
| M22 | `_grammar.py` | no type checks | killed | `tests/test_contract_api.py::test_wrong_types_raise_type_error[int` |
| M23 | `_model.py` | repr shows the token68 | killed | `src/authchallenge/__init__.py::authchallenge.Credentials` |
| M24 | `_helpers.py` | scheme compared with case | killed | `src/authchallenge/_helpers.py::authchallenge._helpers.select_challenge` |
| M25 | `_build.py` | realm not always quoted | killed | `src/authchallenge/_build.py::authchallenge._build.build_challenge` |
| M26 | `_build.py` | names equal without case accepted | killed | `tests/test_build.py::test_build_rejects_names_that_differ_only_in_case` |
| M27 | `_build.py` | token68 and params both built | killed | `tests/test_build.py::test_build_rejects_both_token68_and_params` |
| M28 | `_schemes.py` | realm rule applied to credentials | killed | `tests/test_review_fixes.py::test_realm_quoting_is_required_of_challenges_only` |
| M29 | `_schemes.py` | Digest credentials without username | killed | `tests/test_schemes.py::test_credentials_rules[x=1,` |
| M30 | `_cli.py` | CLI strict exits 0 | killed | `tests/test_cli.py::test_strict_reports_the_rule_and_exits_one` |
| M31 | `_drafts.py` | field line numbers off by one | killed | `tests/test_review_fixes.py::test_offsets_point_at_the_junk_and_name_the_line` |
| M32 | `_basic.py` | bare token68 quoted in the message | killed | `tests/test_contract_api.py::test_messages_never_quote_a_token68[<lambda>0]` |
| M33 | `_helpers.py` | scope tokens joined by commas | killed | `src/authchallenge/_helpers.py::authchallenge._helpers.build_bearer_challenge` |
| M34 | `_parse.py` | empty field accepted strictly | killed | `tests/test_fuzz.py::test_strict_challenges_accept_exactly_the_grammar[1]` |
| M35 | `_build.py` | list params reach the builder | killed | `tests/test_contract_api.py::test_wrong_types_raise_type_error[params` |
| M36 | `_drafts.py` | bytes iterated as lines | killed | `tests/test_contract_api.py::test_wrong_types_raise_type_error[bytes` |
| M37 | `_extvalue.py` | surrogate leaks UnicodeEncodeError | killed | `tests/test_contract_api.py::test_a_lone_surrogate_is_an_auth_error_everywhere` |
| M38 | `_schemes.py` | Digest challenge without qop | killed | `tests/test_schemes.py::test_challenge_rules[Digest` |
| M39 | `_grammar.py` | token68 allows one '=' only | killed | `src/authchallenge/_basic.py::authchallenge._basic.decode_basic` |
| M40 | `_drafts.py` | params continue across field lines | killed | `tests/test_review_fixes.py::test_a_bare_newline_ends_a_field_line_in_tolerant_mode` |
| M41 | `_basic.py` | surplus padding allowed (`padding > 2` made `padding > 4`) | killed on 3.11.5 | `tests/test_contract_edges.py::test_basic_refuses_surplus_or_short_padding_on_every_python[dTpw====]` |
| M42 | `_basic.py` | length check dropped (`len(token68) % 4 or` removed) | killed on 3.11.5 | `tests/test_contract_edges.py::test_basic_refuses_surplus_or_short_padding_on_every_python[QWxhZGRpbjpvcGVu=]` |

M41 and M42 guard the padding fix found by the interpreter matrix. They were run on
CPython 3.11.5 against `tests/test_contract_edges.py`, because 3.12 and later already refuse
surplus padding inside `base64.b64decode`: there the two mutants change nothing and are
equivalent.

| M43 | `_scan.py` | strict mode lets a tab follow the scheme (`if "\t" in space:` made `if False:`) | killed | `tests/test_strict.py::test_strict_reasons[Basic\trealm="x"-...]` |

M43 was run on this PC (CPython 3.13.2) against the strict, fuzz, greenbytes and scheme
tests. It stands in for the first form of M08, which the earlier pass recorded only as
"strict accepts a tab after the scheme" and which survived there.

Earlier passes of this round, at older heads, also left M13 (a seven-digit `nc`), M15
(U+001F in Basic) and M17 (an `ascii` Basic charset) alive, and M07 (a backslash outside
quotes) was caught only by the 0.2.0 oracle. The contracts in
`tests/test_contract_edges.py` were added for them (5c17de5); all are killed above. M09 was
first written so that it did not compile and was corrected before this run.
