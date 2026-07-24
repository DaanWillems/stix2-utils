from stix2utils.pattern import (
    ComparisonExpressionNode,
    ExpressionNode,
    ObjectPathNode,
    ObservationExpressionNode,
    Parser,
    RootExpressionNode,
    TokenType,
    ValueNode,
)


def test_parser_basic():
    ast = Parser().parse("[network-traffic:dst_ref[1].type = 'ipv4-addr']")
    assert type(ast) is RootExpressionNode
    assert type(ast.left) is ObjectPathNode
    assert ast.left.object_type == "network-traffic"
    assert ast.left.path == "dst_ref[1].type"

    assert ast.operator is TokenType.EQUALS

    assert type(ast.right) is ValueNode
    assert ast.right.value == "ipv4-addr"


def read_node(node):
    values = []
    tmp_values = []
    if type(node.left) is ObservationExpressionNode or type(node.left) is ComparisonExpressionNode:
        tmp_values += read_node(node.left)
    if type(node.right) is ObservationExpressionNode or type(node.left) is ComparisonExpressionNode:
        tmp_values += read_node(node.right)

    if node.operator is TokenType.AND and len(tmp_values) == 2 and all(tmp["object"] == "network-traffic" for tmp in tmp_values):
        if "type" in tmp_values[0]["path"]:
            tmp_values[1]["type"] = tmp_values[0]["value"]
            values.append(tmp_values[1])
        if "type" in tmp_values[1]["path"]:
            tmp_values[0]["type"] = tmp_values[1]["value"]
            values.append(tmp_values[0])
    elif node.operator is TokenType.AND:
        return []
    elif node.operator is TokenType.OR:
        values = tmp_values

    if type(node.left) is ObjectPathNode and node.operator is TokenType.EQUALS:
        values += [{"object": node.left.object_type, "path": node.left.path, "value": node.right.value}]
    if type(node.right) is ExpressionNode:
        values += read_node(node.right)

    return values


def test_parser_extract_single_match_observables():
    ast = Parser().parse(
        "[network-traffic:dst_ref.type = 'ipv4' AND network-traffic:dst_ref.value = '2.2.2.2' "
        "OR network-traffic:src_ref.value = 'google.com' AND network-traffic:src_ref.type = 'domain'] "
        "OR [network-traffic:dst_ref.value = '1.1.1.1' AND network-traffic:dst_ref.type = 'ipv4']"
    )

    assert read_node(ast) == [
        {"object": "network-traffic", "path": "dst_ref.value", "value": "2.2.2.2", "type": "ipv4"},
        {"object": "network-traffic", "path": "src_ref.value", "value": "google.com", "type": "domain"},
        {"object": "network-traffic", "path": "dst_ref.value", "value": "1.1.1.1", "type": "ipv4"},
    ]


def test_parser_issubset():
    ast = Parser().parse("[ipv4-addr:value ISSUBSET '198.51.100.0/24']")
    assert type(ast) is RootExpressionNode
    assert type(ast.left) is ObjectPathNode
    assert ast.left.object_type == "ipv4-addr"
    assert ast.left.path == "value"

    assert ast.operator is TokenType.ISSUBSET

    assert type(ast.right) is ValueNode
    assert ast.right.value == "198.51.100.0/24"


def test_parser_sha():
    ast = Parser().parse("[file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f']")
    assert type(ast) is RootExpressionNode
    assert type(ast.left) is ObjectPathNode
    assert ast.left.object_type == "file"
    assert ast.left.path == "hashes.SHA-256"

    assert ast.operator is TokenType.EQUALS

    assert type(ast.right) is ValueNode
    assert ast.right.value == "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f"


def test_parser_parenthesis():
    ast = Parser().parse("([file:hashes.'SHA-256' = 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f'])")
    assert ast


def test_parser_followedby():
    ast = Parser().parse("[ network-traffic:src_ref.value = '203.0.113.10'] FOLLOWEDBY [network-traffic:dst_ref.value != '198.51.100.58' ]")
    assert type(ast) is RootExpressionNode
    assert type(ast.left) is ObservationExpressionNode
    assert type(ast.right) is ObservationExpressionNode
    assert type(ast.left.left) is ObjectPathNode
    assert type(ast.right.left) is ObjectPathNode
    assert type(ast.left.right) is ValueNode
    assert type(ast.right.right) is ValueNode
    assert ast.operator is TokenType.FOLLOWEDBY

    assert ast.left.left.object_type == "network-traffic"
    assert ast.left.left.path == "src_ref.value"
    assert ast.left.right.value == "203.0.113.10"
    assert ast.left.operator is TokenType.EQUALS

    assert ast.right.left.object_type == "network-traffic"
    assert ast.right.left.path == "dst_ref.value"
    assert ast.right.right.value == "198.51.100.58"
    assert ast.right.operator is TokenType.NOT_EQUALS


def test_parser_and():
    ast = Parser().parse("[ network-traffic:src_ref.value = '203.0.113.10' AND network-traffic:dst_ref.value != '198.51.100.58' ]")
    assert type(ast) is RootExpressionNode
    assert type(ast.left) is ComparisonExpressionNode
    assert type(ast.right) is ComparisonExpressionNode
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
    ast = Parser().parse(
        "[ network-traffic:src_ref.value = '203.0.113.10' AND network-traffic:dst_ref.value != '198.51.100.58' "
        "OR network-traffic:dst_ref.value = '127.0.0.1' ]"
    )
    assert type(ast) is RootExpressionNode
    assert type(ast.left) is ComparisonExpressionNode
    assert type(ast.right) is ComparisonExpressionNode
    assert type(ast.left.left) is ComparisonExpressionNode
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


def test_parser_observation_expression_qualifier():
    assert Parser().parse(
        "[network-traffic:dst_ref.value = 'example.com'] AND [network-traffic:dst_ref.value = 'example.com'] "
        "REPEATS 5 TIMES WITHIN 1800 SECONDS"
    )


def test_parser_observation_r():
    assert Parser().parse(
        "[ network-traffic:src_ref.value = '203.0.113.10' AND network-traffic:dst_ref.value != '198.51.100.58' "
        "OR network-traffic:dst_ref.value = '127.0.0.1' ] OR [ipv4-addr:value = '198.51.100.0']"
    )
