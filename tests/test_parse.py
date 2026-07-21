from stix2utils.pattern import ExpressionNode, ObjectPathNode, Parser, Tokenizer, TokenType, ValueNode


def test_parser_basic():
    tokens = Tokenizer().process("[network-traffic:dst_ref[1].type = 'ipv4-addr'")
    ast = Parser().process(tokens)
    assert type(ast) is ExpressionNode
    assert type(ast.left) is ObjectPathNode
    assert ast.left.object_type == "network-traffic"
    assert ast.left.path == "dst_ref[1].type"

    assert ast.operator is TokenType.EQUALS

    assert type(ast.right) is ValueNode
    assert ast.right.value == "ipv4-addr"


def test_parser_issubset():
    tokens = Tokenizer().process("[ipv4-addr:value ISSUBSET '198.51.100.0/24']")
    ast = Parser().process(tokens)
    assert type(ast) is ExpressionNode
    assert type(ast.left) is ObjectPathNode
    assert ast.left.object_type == "ipv4-addr"
    assert ast.left.path == "value"

    assert ast.operator is TokenType.ISSUBSET

    assert type(ast.right) is ValueNode
    assert ast.right.value == "198.51.100.0/24"
