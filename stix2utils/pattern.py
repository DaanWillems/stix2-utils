from dataclasses import dataclass
from enum import Enum, auto

from stix2utils.common import Timestamp


class UnexpectedEODError(Exception):
    pass


class TokenType(Enum):
    OPEN_BRACKET = auto()
    CLOSE_BRACKET = auto()
    OPEN_BRACE = auto()
    CLOSE_BRACE = auto()
    DOT = auto()
    DOUBLE_DOT = auto()
    EQUALS = auto()
    NOT_EQUALS = auto()
    GREATER = auto()
    GREATER_EQ = auto()
    LESSER = auto()
    LESSER_EQ = auto()
    STR = auto()
    QUOTED_STR = auto()
    AND = auto()
    OR = auto()
    REPEATS = auto()
    TIMES = auto()
    WITHIN = auto()
    SECONDS = auto()
    START = auto()
    STOP = auto()
    FOLLOWEDBY = auto()
    EXISTS = auto()
    ISSUPERSET = auto()
    ISSUBSET = auto()
    IN = auto()
    LIKE = auto()
    MATCHES = auto()


PRECEDENCE = {
    TokenType.OR: 1,
    TokenType.AND: 2,
    TokenType.FOLLOWEDBY: 3,
}


@dataclass
class Token:
    token_type: TokenType
    original_value: str


class Tokenizer:
    def process(self, raw_str_input: str) -> list[Token]:
        tokens = []
        chars = list(raw_str_input)
        chars.reverse()
        while True:
            if len(chars) == 0:
                break
            match chars[-1]:
                case "[":
                    tokens.append(Token(token_type=TokenType.OPEN_BRACKET, original_value=chars.pop()))
                case "]":
                    tokens.append(Token(token_type=TokenType.CLOSE_BRACKET, original_value=chars.pop()))
                case "(":
                    tokens.append(Token(token_type=TokenType.OPEN_BRACE, original_value=chars.pop()))
                case ")":
                    tokens.append(Token(token_type=TokenType.CLOSE_BRACE, original_value=chars.pop()))
                case "=":
                    tokens.append(Token(token_type=TokenType.EQUALS, original_value=chars.pop()))
                case "!":
                    if chars[-2] == "=":
                        tokens.append(Token(token_type=TokenType.NOT_EQUALS, original_value=chars.pop() + chars.pop()))
                case ">":
                    if chars[-2] == "=":
                        tokens.append(Token(token_type=TokenType.GREATER_EQ, original_value=chars.pop() + chars.pop()))
                    else:
                        tokens.append(Token(token_type=TokenType.GREATER, original_value=chars.pop()))
                case "<":
                    if chars[-2] == "=":
                        tokens.append(Token(token_type=TokenType.LESSER_EQ, original_value=chars.pop() + chars.pop()))
                    else:
                        tokens.append(Token(token_type=TokenType.LESSER, original_value=chars.pop()))
                case ".":
                    tokens.append(Token(token_type=TokenType.DOT, original_value=chars.pop()))
                case ":":
                    tokens.append(Token(token_type=TokenType.DOUBLE_DOT, original_value=chars.pop()))
                case "'":
                    tokens.append(self._process_quoted_str(chars))
                case " ":
                    chars.pop()
                case _:
                    tokens.append(self._process_str(chars))
        return tokens

    def _process_str(self, chars: list) -> Token:
        value = ""
        while True:
            if len(chars) == 0:
                keyword_token = self._match_keyword(value)
                if keyword_token:
                    return keyword_token
                return Token(token_type=TokenType.STR, original_value=value)

            match chars[-1]:
                case " ":
                    chars.pop()
                    keyword_token = self._match_keyword(value)
                    if keyword_token:
                        return keyword_token
                    return Token(token_type=TokenType.STR, original_value=value)
                case "[" | "]" | "=" | ":" | "." | ">" | "<" | "!":
                    keyword_token = self._match_keyword(value)
                    if keyword_token:
                        return keyword_token
                    return Token(token_type=TokenType.STR, original_value=value)
                case _:
                    value += chars.pop()

    def _match_keyword(self, chars: str) -> Token | None:
        token = None
        match chars:
            case "AND":
                token = Token(token_type=TokenType.AND, original_value=chars)
            case "OR":
                token = Token(token_type=TokenType.OR, original_value=chars)
            case "REPEATS":
                token = Token(token_type=TokenType.REPEATS, original_value=chars)
            case "TIMES":
                token = Token(token_type=TokenType.TIMES, original_value=chars)
            case "WITHIN":
                token = Token(token_type=TokenType.WITHIN, original_value=chars)
            case "SECONDS":
                token = Token(token_type=TokenType.SECONDS, original_value=chars)
            case "START":
                token = Token(token_type=TokenType.START, original_value=chars)
            case "STOP":
                token = Token(token_type=TokenType.STOP, original_value=chars)
            case "FOLLOWEDBY":
                token = Token(token_type=TokenType.FOLLOWEDBY, original_value=chars)
            case "MATCHES":
                token = Token(token_type=TokenType.MATCHES, original_value=chars)
            case "IN":
                token = Token(token_type=TokenType.IN, original_value=chars)
            case "LIKE":
                token = Token(token_type=TokenType.LIKE, original_value=chars)
            case "ISSUPERSET":
                token = Token(token_type=TokenType.ISSUPERSET, original_value=chars)
            case "ISSUBSET":
                token = Token(token_type=TokenType.ISSUBSET, original_value=chars)
        return token

    def _process_quoted_str(self, chars: list) -> Token:
        chars.pop()  # Read first quote
        value = ""
        while True:
            if len(chars) == 0:
                msg = "Unexpected <EOD>"
                raise RuntimeError(msg)
            match chars[-1]:
                case "'":
                    chars.pop()
                    return Token(token_type=TokenType.QUOTED_STR, original_value=value)
                case _:
                    value += chars.pop()


@dataclass
class ASTNode:
    pass


@dataclass
class ExpressionNode(ASTNode):
    left: ASTNode
    right: ASTNode
    operator: TokenType


@dataclass
class RootExpressionNode(ExpressionNode):
    pass


@dataclass
class ObservationExpressionNode(ExpressionNode):
    pass


@dataclass
class ComparisonExpressionNode(ExpressionNode):
    pass


@dataclass
class ObjectPathNode(ASTNode):
    object_type: str
    path: str


@dataclass
class ValueNode(ASTNode):
    value: str


@dataclass
class ObservationalQualiferNode(ASTNode):
    expression: ExpressionNode


@dataclass
class RepeatNode(ObservationalQualiferNode):
    repeat_times: int


@dataclass
class WithinNode(ObservationalQualiferNode):
    seconds: int


@dataclass
class StartStopNode(ObservationalQualiferNode):
    start: Timestamp
    stop: Timestamp


class Parser:
    def _parse_object_value(self, tokens: list[Token]) -> ValueNode:
        if tokens[-1].token_type != TokenType.QUOTED_STR:
            msg = "Expected a quoted string"
            raise RuntimeError(msg)

        return ValueNode(tokens.pop().original_value)

    def _parse_object_path(self, tokens: list[Token]) -> ObjectPathNode:
        if tokens[-1].token_type != TokenType.STR:
            msg = "Expected a string"
            raise RuntimeError(msg)

        object_type = tokens.pop().original_value

        if tokens[-1].token_type != TokenType.DOUBLE_DOT:
            msg = "Expected a colon"
            raise RuntimeError(msg)

        tokens.pop()

        if tokens[-1].token_type != TokenType.STR:
            msg = "Expected a string"
            raise RuntimeError(msg)

        value = tokens.pop().original_value

        if tokens[-1].token_type == TokenType.OPEN_BRACKET:
            tokens.pop()
            if tokens[-1].token_type != TokenType.STR:
                msg = "Expected a string"
                raise RuntimeError(msg)
            array_index = tokens.pop().original_value
            if tokens[-1].token_type != TokenType.CLOSE_BRACKET:
                msg = "Expected a closing bracket"
                raise RuntimeError(msg)
            tokens.pop()
            value += f"[{array_index}]"

        if tokens[-1].token_type == TokenType.DOT:
            tokens.pop()
            if tokens[-1].token_type != TokenType.STR and tokens[-1].token_type != TokenType.QUOTED_STR:
                msg = "Expected a string"
                raise RuntimeError(msg)
            value += f".{tokens.pop().original_value}"

        return ObjectPathNode(object_type=object_type, path=value)

    def _parse_inner_binary(self, tokens: list[Token], min_prec: int = 1) -> ExpressionNode:
        left = self._parse_sub_expression(tokens)
        while tokens and (prec := PRECEDENCE.get(tokens[-1].token_type, 0)) >= min_prec:
            op = tokens.pop().token_type
            right = self._parse_inner_binary(tokens, prec + 1)  # +1 => left associative
            left = ComparisonExpressionNode(left=left, operator=op, right=right)
        return left

    def _parse_expression(self, tokens: list[Token]) -> ExpressionNode:
        tok = tokens.pop()
        match tok.token_type:
            case TokenType.OPEN_BRACE:
                expression = self._parse_binary(tokens, 1)  # reset to lowest precedence
            case TokenType.OPEN_BRACKET:
                n_expression = self._parse_inner_binary(tokens)
                expression = ObservationExpressionNode(left=n_expression.left, operator=n_expression.operator, right=n_expression.right)
            case _:
                msg = f"unexpected {tok.token_type}"
                raise RuntimeError(msg)

        if len(tokens) < 1 or (tokens[-1].token_type is not TokenType.CLOSE_BRACKET and tokens[-1].token_type is not TokenType.CLOSE_BRACE):
            raise RuntimeError
        tokens.pop()

        while True:
            if len(tokens) == 0:
                break
            match tokens[-1].token_type:
                case TokenType.REPEATS:
                    tokens.pop()
                    value = tokens.pop().original_value
                    expression = RepeatNode(expression=expression, repeat_times=int(value))
                    if tokens[-1].token_type is TokenType.TIMES:
                        tokens.pop()
                    else:
                        raise RuntimeError
                case TokenType.WITHIN:
                    tokens.pop()
                    value = tokens.pop().original_value
                    expression = WithinNode(expression=expression, seconds=int(value))
                    if tokens[-1].token_type is TokenType.SECONDS:
                        tokens.pop()
                    else:
                        raise RuntimeError
                case _:
                    break

        return expression

    def _parse_sub_expression(self, tokens: list[Token]) -> ExpressionNode:
        left = self._parse_object_path(tokens)

        match tokens[-1].token_type:
            case (
                TokenType.EQUALS
                | TokenType.NOT_EQUALS
                | TokenType.LESSER
                | TokenType.LESSER_EQ
                | TokenType.GREATER
                | TokenType.GREATER_EQ
                | TokenType.ISSUBSET
                | TokenType.ISSUPERSET
                | TokenType.IN
                | TokenType.LIKE
                | TokenType.MATCHES
            ):
                pass
            case TokenType.NOT_EQUALS:
                pass
            case _:
                msg = "Expected a comparison operator"
                raise RuntimeError(msg)

        operator = tokens.pop().token_type

        right = self._parse_object_value(tokens)

        return ComparisonExpressionNode(left=left, operator=operator, right=right)

    def _parse_binary(self, tokens: list[Token], min_prec: int = 1) -> ExpressionNode:
        left = self._parse_expression(tokens)
        while tokens and (prec := PRECEDENCE.get(tokens[-1].token_type, 0)) >= min_prec:
            op = tokens.pop().token_type
            right = self._parse_binary(tokens, prec + 1)  # +1 => left associative
            left = ExpressionNode(left=left, operator=op, right=right)
        return left

    def parse(self, input_str: str) -> ASTNode:
        tokens = Tokenizer().process(input_str)
        tokens.reverse()
        n_expression = self._parse_binary(tokens)
        return RootExpressionNode(left=n_expression.left, operator=n_expression.operator, right=n_expression.right)
