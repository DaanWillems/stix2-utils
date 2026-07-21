import pytest

from stix2utils.pattern import Token, Tokenizer, TokenType, UnexpectedEODError


def test_tokenize_unexpected_eod():
    with pytest.raises(UnexpectedEODError):
        Tokenizer().process("[network-traffic:dst_ref.type = 'ipv4-addr' AN")


def test_tokenize_weird_pattern():
    assert Tokenizer().process("xqwqw") == [Token(token_type=TokenType.STR, original_value="xqwqw")]


def test_tokenize_lesser_eq():
    assert Tokenizer().process("a <= b") == [
        Token(token_type=TokenType.STR, original_value="a"),
        Token(token_type=TokenType.LESSER_EQ, original_value="<="),
        Token(token_type=TokenType.STR, original_value="b"),
    ]


def test_tokenize_complex_pattern():
    assert Tokenizer().process(
        "[process:command_line MATCHES '^.+>-add GlobalSign.cer -c -s -r localMachine Root$'] FOLLOWEDBY [process:command_line MATCHES'^.+>-add GlobalSign.cer -c -s -r localMachineTrustedPublisher$'] WITHIN 300 SECONDS"
    )


def test_tokenize_escape():
    # Smoke test for no error
    assert Tokenizer().process(
        "[artifact:mime_type = 'application/vnd.tcpdump.pcap' AND artifact:payload_bin MATCHES '\\xd4\\xc3\\xb2\\xa1\\x02\\x00\\x04\\x00']"
    )


def test_tokenize_brackets():
    # Smoke test for no error
    assert Tokenizer().process("[domain-name:value = 'www.5z8.info' AND domain-name:resolves_to_refs[*].value = '198.51.100.1/32']")


def test_tokenize_repeats():
    tokenizer = Tokenizer()
    tokens = tokenizer.process(
        "[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '203.0.113.33/32'] REPEATS 5 TIMES WITHIN 1800 SECONDS"
    )
    assert tokens == [
        Token(token_type=TokenType.OPEN_BRACKET, original_value="["),
        Token(token_type=TokenType.STR, original_value="network-traffic"),
        Token(token_type=TokenType.DOUBLE_DOT, original_value=":"),
        Token(token_type=TokenType.STR, original_value="dst_ref"),
        Token(token_type=TokenType.DOT, original_value="."),
        Token(token_type=TokenType.STR, original_value="type"),
        Token(token_type=TokenType.EQUALS, original_value="="),
        Token(token_type=TokenType.QUOTED_STR, original_value="ipv4-addr"),
        Token(token_type=TokenType.AND, original_value="AND"),
        Token(token_type=TokenType.STR, original_value="network-traffic"),
        Token(token_type=TokenType.DOUBLE_DOT, original_value=":"),
        Token(token_type=TokenType.STR, original_value="dst_ref"),
        Token(token_type=TokenType.DOT, original_value="."),
        Token(token_type=TokenType.STR, original_value="value"),
        Token(token_type=TokenType.EQUALS, original_value="="),
        Token(token_type=TokenType.QUOTED_STR, original_value="203.0.113.33/32"),
        Token(token_type=TokenType.CLOSE_BRACKET, original_value="]"),
        Token(token_type=TokenType.REPEATS, original_value="REPEATS"),
        Token(token_type=TokenType.STR, original_value="5"),
        Token(token_type=TokenType.TIMES, original_value="TIMES"),
        Token(token_type=TokenType.WITHIN, original_value="WITHIN"),
        Token(token_type=TokenType.STR, original_value="1800"),
        Token(token_type=TokenType.SECONDS, original_value="SECONDS"),
    ]


def test_tokenize_1():
    tokenizer = Tokenizer()
    tokens = tokenizer.process("[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '203.0.113.33/32']")
    assert tokens == [
        Token(token_type=TokenType.OPEN_BRACKET, original_value="["),
        Token(token_type=TokenType.STR, original_value="network-traffic"),
        Token(token_type=TokenType.DOUBLE_DOT, original_value=":"),
        Token(token_type=TokenType.STR, original_value="dst_ref"),
        Token(token_type=TokenType.DOT, original_value="."),
        Token(token_type=TokenType.STR, original_value="type"),
        Token(token_type=TokenType.EQUALS, original_value="="),
        Token(token_type=TokenType.QUOTED_STR, original_value="ipv4-addr"),
        Token(token_type=TokenType.AND, original_value="AND"),
        Token(token_type=TokenType.STR, original_value="network-traffic"),
        Token(token_type=TokenType.DOUBLE_DOT, original_value=":"),
        Token(token_type=TokenType.STR, original_value="dst_ref"),
        Token(token_type=TokenType.DOT, original_value="."),
        Token(token_type=TokenType.STR, original_value="value"),
        Token(token_type=TokenType.EQUALS, original_value="="),
        Token(token_type=TokenType.QUOTED_STR, original_value="203.0.113.33/32"),
        Token(token_type=TokenType.CLOSE_BRACKET, original_value="]"),
    ]


def test_tokenize_2():
    tokenizer = Tokenizer()
    tokens = tokenizer.process(
        "[user-account:account_type = 'unix' AND user-account:user_id = '1007' AND user-account:account_login = 'Peter'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1008' AND user-account:account_login = 'Paul'] AND [user-account:account_type = 'unix' AND user-account:user_id = '1009' AND user-account:account_login = 'Mary']"
    )
    assert tokens == [
        Token(token_type=TokenType.OPEN_BRACKET, original_value="["),
        Token(token_type=TokenType.STR, original_value="user-account"),
        Token(token_type=TokenType.DOUBLE_DOT, original_value=":"),
        Token(token_type=TokenType.STR, original_value="account_type"),
        Token(token_type=TokenType.EQUALS, original_value="="),
        Token(token_type=TokenType.QUOTED_STR, original_value="unix"),
        Token(token_type=TokenType.AND, original_value="AND"),
        Token(token_type=TokenType.STR, original_value="user-account"),
        Token(token_type=TokenType.DOUBLE_DOT, original_value=":"),
        Token(token_type=TokenType.STR, original_value="user_id"),
        Token(token_type=TokenType.EQUALS, original_value="="),
        Token(token_type=TokenType.QUOTED_STR, original_value="1007"),
        Token(token_type=TokenType.AND, original_value="AND"),
        Token(token_type=TokenType.STR, original_value="user-account"),
        Token(token_type=TokenType.DOUBLE_DOT, original_value=":"),
        Token(token_type=TokenType.STR, original_value="account_login"),
        Token(token_type=TokenType.EQUALS, original_value="="),
        Token(token_type=TokenType.QUOTED_STR, original_value="Peter"),
        Token(token_type=TokenType.CLOSE_BRACKET, original_value="]"),
        Token(token_type=TokenType.AND, original_value="AND"),
        Token(token_type=TokenType.OPEN_BRACKET, original_value="["),
        Token(token_type=TokenType.STR, original_value="user-account"),
        Token(token_type=TokenType.DOUBLE_DOT, original_value=":"),
        Token(token_type=TokenType.STR, original_value="account_type"),
        Token(token_type=TokenType.EQUALS, original_value="="),
        Token(token_type=TokenType.QUOTED_STR, original_value="unix"),
        Token(token_type=TokenType.AND, original_value="AND"),
        Token(token_type=TokenType.STR, original_value="user-account"),
        Token(token_type=TokenType.DOUBLE_DOT, original_value=":"),
        Token(token_type=TokenType.STR, original_value="user_id"),
        Token(token_type=TokenType.EQUALS, original_value="="),
        Token(token_type=TokenType.QUOTED_STR, original_value="1008"),
        Token(token_type=TokenType.AND, original_value="AND"),
        Token(token_type=TokenType.STR, original_value="user-account"),
        Token(token_type=TokenType.DOUBLE_DOT, original_value=":"),
        Token(token_type=TokenType.STR, original_value="account_login"),
        Token(token_type=TokenType.EQUALS, original_value="="),
        Token(token_type=TokenType.QUOTED_STR, original_value="Paul"),
        Token(token_type=TokenType.CLOSE_BRACKET, original_value="]"),
        Token(token_type=TokenType.AND, original_value="AND"),
        Token(token_type=TokenType.OPEN_BRACKET, original_value="["),
        Token(token_type=TokenType.STR, original_value="user-account"),
        Token(token_type=TokenType.DOUBLE_DOT, original_value=":"),
        Token(token_type=TokenType.STR, original_value="account_type"),
        Token(token_type=TokenType.EQUALS, original_value="="),
        Token(token_type=TokenType.QUOTED_STR, original_value="unix"),
        Token(token_type=TokenType.AND, original_value="AND"),
        Token(token_type=TokenType.STR, original_value="user-account"),
        Token(token_type=TokenType.DOUBLE_DOT, original_value=":"),
        Token(token_type=TokenType.STR, original_value="user_id"),
        Token(token_type=TokenType.EQUALS, original_value="="),
        Token(token_type=TokenType.QUOTED_STR, original_value="1009"),
        Token(token_type=TokenType.AND, original_value="AND"),
        Token(token_type=TokenType.STR, original_value="user-account"),
        Token(token_type=TokenType.DOUBLE_DOT, original_value=":"),
        Token(token_type=TokenType.STR, original_value="account_login"),
        Token(token_type=TokenType.EQUALS, original_value="="),
        Token(token_type=TokenType.QUOTED_STR, original_value="Mary"),
        Token(token_type=TokenType.CLOSE_BRACKET, original_value="]"),
    ]
