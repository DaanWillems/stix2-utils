from stix2utils.pattern import ExpressionNode, ObjectPathNode, Parser, Tokenizer, TokenType, ValueNode


def test_parser_basic():
    tokens = Tokenizer().process("[network-traffic:dst_ref[1].type = 'ipv4-addr']")
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

def test_parser_sha():
    tokens = Tokenizer().process("[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']")
    ast = Parser().process(tokens)
    assert type(ast) is ExpressionNode
    assert type(ast.left) is ObjectPathNode
    assert ast.left.object_type == "file"
    assert ast.left.path == "hashes.SHA-256"

    assert ast.operator is TokenType.EQUALS

    assert type(ast.right) is ValueNode
    assert ast.right.value == "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f"

def test_parser_and():
    tokens = Tokenizer().process("[ network-traffic:src_ref.value = '203.0.113.10' AND network-traffic:dst_ref.value != '198.51.100.58' ]")
    ast = Parser().process(tokens)
    assert type(ast) is ExpressionNode
    assert type(ast.left) is ExpressionNode
    assert type(ast.right) is ExpressionNode
    assert type(ast.left.left) is ObjectPathNode
    assert type(ast.right.left) is ObjectPathNode
    assert type(ast.left.right) is ValueNode
    assert type(ast.right.right) is ValueNode
    assert ast.operator is TokenType.AND

    assert ast.left.left.object_type == "network-traffic"
    assert ast.left.left.path == "src_ref.value"
    assert ast.left.right.value == "203.0.113.10"
    assert ast.left.operator is TokenType.EQUALS

    assert ast.right.left.object_type == "network-traffic"
    assert ast.right.left.path == "dst_ref.value"
    assert ast.right.right.value == "198.51.100.58"
    assert ast.right.operator is TokenType.NOT_EQUALS

def test_parser_and_or():
    tokens = Tokenizer().process("[ network-traffic:src_ref.value = '203.0.113.10' AND network-traffic:dst_ref.value != '198.51.100.58' OR network-traffic:dst_ref.value = '127.0.0.1' ]")
    ast = Parser().process(tokens)
    assert type(ast) is ExpressionNode
    assert type(ast.left) is ExpressionNode
    assert type(ast.right) is ExpressionNode
    assert type(ast.left.left) is ExpressionNode
    assert type(ast.left.left.left) is ObjectPathNode
    assert type(ast.left.left.right) is ValueNode

    assert type(ast.right.left) is ObjectPathNode
    assert type(ast.right.right) is ValueNode

    assert ast.operator is TokenType.OR
    assert ast.left.operator is TokenType.AND

    assert ast.left.left.left.object_type == "network-traffic"
    assert ast.left.left.left.path == "src_ref.value"
    assert ast.left.left.right.value == "203.0.113.10"
    assert ast.left.left.operator is TokenType.EQUALS


    assert ast.left.right.left.object_type == "network-traffic"
    assert ast.left.right.left.path == "dst_ref.value"
    assert ast.left.right.right.value == "198.51.100.58"
    assert ast.left.right.operator is TokenType.NOT_EQUALS

    assert ast.right.left.object_type == "network-traffic"
    assert ast.right.left.path == "dst_ref.value"
    assert ast.right.right.value == "127.0.0.1"
    assert ast.right.operator is TokenType.EQUALS
