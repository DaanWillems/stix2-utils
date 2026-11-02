"""Regression tests for known bugs in the STIX 2.1 pattern parser.

Every test here describes the *correct* behaviour and currently fails, so each one
is marked ``xfail(strict=True)``. The suite stays green while the bug exists. Once a
bug is fixed its test passes unexpectedly, and strict mode turns that into a failure
as a reminder to remove the ``xfail`` marker.

Syntax errors are expected to raise ``SYNTAX_ERROR``. The parser currently uses
``RuntimeError`` for these. If a dedicated exception type is introduced, update the
constant below (or make the new exception a subclass of ``RuntimeError``).

The tests only rely on the current AST where a bug cannot be expressed otherwise
(operator precedence). Everything else walks the tree generically so the tests
survive an AST redesign.
"""

import dataclasses
import subprocess
import sys

import pytest

from stix2utils.pattern import (
    ObjectPathNode,
    Parser,
    RepeatNode,
    StartStopNode,
    Tokenizer,
    TokenType,
    ValueNode,
    WithinNode,
)

SYNTAX_ERROR = RuntimeError


def bug(reason: str) -> pytest.MarkDecorator:
    return pytest.mark.xfail(strict=True, reason=reason)


def walk(node: object) -> list[object]:
    """Return ``node`` and every AST node nested inside it."""
    nodes = [node]
    if dataclasses.is_dataclass(node) and not isinstance(node, type):
        for f in dataclasses.fields(node):
            nodes.extend(walk(getattr(node, f.name)))
    elif isinstance(node, (list, tuple)):
        for item in node:
            nodes.extend(walk(item))
    return nodes


def nodes_of_type(node: object, node_type: type) -> list:
    return [n for n in walk(node) if isinstance(n, node_type)]


# ---------------------------------------------------------------------------
# 1. Observation operator precedence.
#    STIX 2.1 precedence, tightest to loosest: AND, OR, FOLLOWEDBY.
# ---------------------------------------------------------------------------


@bug("FOLLOWEDBY binds tighter than OR; it should bind loosest")
def test_followedby_binds_looser_than_or_on_the_right() -> None:
    # Must be (A OR B) FOLLOWEDBY C
    ast = Parser().parse("[a:b = '1'] OR [a:b = '2'] FOLLOWEDBY [a:b = '3']")

    assert ast.operator is TokenType.FOLLOWEDBY
    assert ast.left.operator is TokenType.OR


@bug("FOLLOWEDBY binds tighter than AND; it should bind loosest")
def test_followedby_binds_looser_than_and() -> None:
    # Must be (A AND B) FOLLOWEDBY C
    ast = Parser().parse("[a:b = '1'] AND [a:b = '2'] FOLLOWEDBY [a:b = '3']")

    assert ast.operator is TokenType.FOLLOWEDBY
    assert ast.left.operator is TokenType.AND


# ---------------------------------------------------------------------------
# 2. Unconsumed trailing tokens are silently ignored.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        "[file:name = 'a'] ]",
        "[file:name = 'a'] foo",
        "[file:name = 'a'] [file:name = 'b']",
    ],
)
@bug("tokens left over after parsing are silently dropped")
def test_trailing_tokens_are_rejected(pattern: str) -> None:
    with pytest.raises(SYNTAX_ERROR):
        Parser().parse(pattern)


@bug("START/STOP qualifier is silently dropped (StartStopNode is never produced)")
def test_start_stop_qualifier_is_parsed() -> None:
    ast = Parser().parse("[file:name = 'a'] START t'2016-01-01T00:00:00Z' STOP t'2017-01-01T00:00:00Z'")

    assert len(nodes_of_type(ast, StartStopNode)) == 1


# ---------------------------------------------------------------------------
# 3. Mismatched brackets/parentheses are accepted.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        "[file:name = 'a')",
        "([file:name = 'a']]",
    ],
)
@bug("closing ']' and ')' are interchangeable")
def test_mismatched_brackets_are_rejected(pattern: str) -> None:
    with pytest.raises(SYNTAX_ERROR):
        Parser().parse(pattern)


# ---------------------------------------------------------------------------
# 4. Qualifier on the top-level observation crashes.
# ---------------------------------------------------------------------------


@bug("parse() reads .left/.operator/.right from a RepeatNode -> AttributeError")
def test_repeats_on_top_level_observation() -> None:
    ast = Parser().parse("[file:name = 'a'] REPEATS 5 TIMES")

    repeats = nodes_of_type(ast, RepeatNode)
    assert len(repeats) == 1
    assert repeats[0].repeat_times == 5


@bug("parse() reads .left/.operator/.right from a WithinNode -> AttributeError")
def test_within_on_top_level_observation() -> None:
    ast = Parser().parse("[file:name = 'a'] WITHIN 10 SECONDS")

    within = nodes_of_type(ast, WithinNode)
    assert len(within) == 1
    assert within[0].seconds == 10


# ---------------------------------------------------------------------------
# 5. FOLLOWEDBY is accepted inside a comparison expression.
# ---------------------------------------------------------------------------


@bug("comparison expressions share the observation precedence table, so FOLLOWEDBY is accepted inside brackets")
def test_followedby_inside_brackets_is_rejected() -> None:
    with pytest.raises(SYNTAX_ERROR):
        Parser().parse("[file:name = 'a' FOLLOWEDBY file:name = 'b']")


# ---------------------------------------------------------------------------
# 6. Tokenizer hangs or crashes on a dangling operator character.
# ---------------------------------------------------------------------------


@bug("a '!' not followed by '=' is never consumed, so the tokenizer loops forever")
def test_lone_exclamation_mark_does_not_hang() -> None:
    # Run in a subprocess so the infinite loop can be killed.
    code = (
        "from stix2utils.pattern import Parser\n"
        "try:\n"
        "    Parser().parse(\"[file:name ! 'a']\")\n"
        "except RuntimeError:\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(1)\n"
    )
    result = subprocess.run([sys.executable, "-c", code], timeout=5, check=False, capture_output=True)  # noqa: S603

    assert result.returncode == 0


@pytest.mark.parametrize("pattern", ["[file:size >", "[file:size <", "[file:size !"])
@bug("chars[-2] lookahead raises IndexError when the operator is the last character")
def test_operator_at_end_of_input_is_a_syntax_error(pattern: str) -> None:
    with pytest.raises(SYNTAX_ERROR):
        Parser().parse(pattern)


# ---------------------------------------------------------------------------
# 7. Keywords directly followed by ')' are not recognised.
# ---------------------------------------------------------------------------


@bug("_process_str does not stop at ')', so 'SECONDS)' becomes a single STR token")
def test_keyword_followed_by_close_paren_is_tokenized_as_keyword() -> None:
    tokens = Tokenizer().process("WITHIN 10 SECONDS)")

    assert [t.token_type for t in tokens] == [TokenType.WITHIN, TokenType.STR, TokenType.SECONDS, TokenType.CLOSE_BRACE]


@bug("qualifier before ')' fails because 'SECONDS)' is not recognised")
def test_qualifier_inside_parentheses() -> None:
    ast = Parser().parse("([file:name = 'a'] WITHIN 10 SECONDS)")

    assert len(nodes_of_type(ast, WithinNode)) == 1


# ---------------------------------------------------------------------------
# 8. Only ' ' is treated as whitespace.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("whitespace", ["\t", "\n", "\r\n"])
@bug("tabs and newlines end up inside STR tokens")
def test_non_space_whitespace_is_ignored(whitespace: str) -> None:
    ast = Parser().parse(f"[file:name{whitespace}={whitespace}'a']")

    paths = nodes_of_type(ast, ObjectPathNode)
    assert [p.path for p in paths] == ["name"]


@bug("multi-line patterns are not tokenized correctly")
def test_multiline_pattern() -> None:
    ast = Parser().parse("[file:name = 'a']\nAND\n[file:name = 'b']")

    assert ast.operator is TokenType.AND


# ---------------------------------------------------------------------------
# Valid STIX 2.1 syntax that is rejected.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        pytest.param("[file:size > 1024]", id="integer"),
        pytest.param("[file:size = -1]", id="negative-integer"),
        pytest.param("[x-foo:score = 1.5]", id="float"),
        pytest.param("[process:is_hidden = true]", id="boolean"),
        pytest.param("[file:created > t'2016-01-01T00:00:00Z']", id="timestamp-literal"),
        pytest.param("[file:magic_number_hex = h'ffd8']", id="hex-literal"),
        pytest.param("[artifact:payload_bin = b'aGVsbG8=']", id="binary-literal"),
    ],
)
@bug("only quoted strings are accepted as comparison values")
def test_non_string_values(pattern: str) -> None:
    assert len(nodes_of_type(Parser().parse(pattern), ObjectPathNode)) == 1


@bug("set literals for IN are not supported")
def test_in_with_set_literal() -> None:
    ast = Parser().parse("[ipv4-addr:value IN ('198.51.100.1', '198.51.100.2')]")

    assert len(nodes_of_type(ast, ObjectPathNode)) == 1


@pytest.mark.parametrize("operator", ["NOT =", "NOT !=", "NOT LIKE", "NOT MATCHES", "NOT ISSUBSET", "NOT ISSUPERSET", "NOT IN"])
@bug("NOT is not supported")
def test_not_operator(operator: str) -> None:
    value = "('a', 'b')" if operator == "NOT IN" else "'a'"
    ast = Parser().parse(f"[file:name {operator} {value}]")

    assert len(nodes_of_type(ast, ObjectPathNode)) == 1


@bug("EXISTS is tokenised as a type but never produced or parsed")
def test_exists_operator() -> None:
    ast = Parser().parse("[EXISTS windows-registry-key:values]")

    assert len(nodes_of_type(ast, ObjectPathNode)) == 1


@bug("escaped quotes in string literals are not handled")
def test_escaped_quote_in_string() -> None:
    ast = Parser().parse("[file:name = 'O\\'Reilly']")

    assert [v.value for v in nodes_of_type(ast, ValueNode)] == ["O'Reilly"]


@pytest.mark.parametrize(
    "pattern",
    [
        "[network-traffic:extensions.'http-request-ext'.request_method = 'get']",
        "[file:extensions.'windows-pebinary-ext'.sections[*].entropy > '7']",
        "[email-message:body_multipart[*].body_raw_ref.name = 'a']",
    ],
)
@bug("object paths support at most one index and one '.property' after the first property")
def test_deep_object_paths(pattern: str) -> None:
    assert len(nodes_of_type(Parser().parse(pattern), ObjectPathNode)) == 1


@bug("parentheses inside a comparison expression are not supported")
def test_parentheses_inside_brackets() -> None:
    ast = Parser().parse("[(file:name = 'a' OR file:name = 'b') AND file:size = '1']")

    assert len(nodes_of_type(ast, ObjectPathNode)) == 3


# ---------------------------------------------------------------------------
# Error handling: malformed input should raise a syntax error, not an
# arbitrary IndexError / ValueError, and the error should explain itself.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern",
    [
        pytest.param("", id="empty"),
        pytest.param("   ", id="only-whitespace"),
        pytest.param("[file:name = 'a'] REPEATS 5", id="repeats-missing-times"),
        pytest.param("[file:name = 'a'] REPEATS", id="repeats-missing-count"),
        pytest.param("[file:name = 'a'] WITHIN 10", id="within-missing-seconds"),
        pytest.param("[file:name = 'a'] REPEATS abc TIMES", id="repeats-non-integer"),
        pytest.param("[file:name = 'a'] WITHIN abc SECONDS", id="within-non-integer"),
        pytest.param("[file:name =", id="missing-value"),
        pytest.param("[file:name", id="missing-operator"),
        pytest.param("[file", id="missing-colon"),
    ],
)
@bug("malformed input leaks IndexError/ValueError instead of a syntax error")
def test_malformed_input_raises_syntax_error(pattern: str) -> None:
    with pytest.raises(SYNTAX_ERROR):
        Parser().parse(pattern)


@pytest.mark.parametrize(
    "pattern",
    [
        pytest.param("[file:name = 'a'", id="missing-close-bracket"),
        pytest.param("[file:name = 'a'] REPEATS 5 SECONDS", id="repeats-wrong-keyword"),
        pytest.param("[file:name = 'a'] WITHIN 5 TIMES", id="within-wrong-keyword"),
    ],
)
@bug("several syntax errors are raised as a bare RuntimeError with no message")
def test_syntax_errors_have_a_message(pattern: str) -> None:
    with pytest.raises(SYNTAX_ERROR) as exc_info:
        Parser().parse(pattern)

    assert str(exc_info.value)
