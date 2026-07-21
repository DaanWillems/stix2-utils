from dataclasses import dataclass
from enum import Enum, auto


class UnexpectedEODError(Exception):
    pass


class TokenType(Enum):
    OPEN_BRACKET = auto()
    CLOSE_BRACKET = auto()
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


@dataclass
class Token:
    token_type: TokenType
    original_value: str


class Tokenizer:
    def process(self, str_input: str) -> list[Token]:
        tokens = []
        str_input = list("".join(str_input.split()))
        str_input.reverse()
        while True:
            if len(str_input) == 0:
                break
            match str_input[-1]:
                case "[":
                    tokens.append(Token(token_type=TokenType.OPEN_BRACKET, original_value=str_input.pop()))
                case "]":
                    tokens.append(Token(token_type=TokenType.CLOSE_BRACKET, original_value=str_input.pop()))
                case "=":
                    tokens.append(Token(token_type=TokenType.EQUALS, original_value=str_input.pop()))
                case ">":
                    if str_input[-2] == "=":
                        tokens.append(Token(token_type=TokenType.GREATER_EQ, original_value=str_input.pop() + str_input.pop()))
                    else:
                        tokens.append(Token(token_type=TokenType.GREATER, original_value=str_input.pop()))
                case "<":
                    if str_input[-2] == "=":
                        tokens.append(Token(token_type=TokenType.LESSER_EQ, original_value=str_input.pop() + str_input.pop()))
                    else:
                        tokens.append(Token(token_type=TokenType.LESSER, original_value=str_input.pop()))
                case ".":
                    tokens.append(Token(token_type=TokenType.DOT, original_value=str_input.pop()))
                case ":":
                    tokens.append(Token(token_type=TokenType.DOUBLE_DOT, original_value=str_input.pop()))
                case "'":
                    tokens.append(self._process_quoted_str(str_input))
                case _:
                    if str_input[-1].isupper():
                        tokens.append(self._process_keyword(str_input))
                    else:
                        tokens.append(self._process_str(str_input))
        return tokens

    def _process_keyword(self, str_input: list) -> Token:
        value = ""
        while True:
            if len(str_input) == 0:
                raise UnexpectedEODError

            value += str_input.pop()
            if not value.isupper():
                raise UnexpectedEODError

            keyword_token = self._match_keyword(value)
            if keyword_token:
                return keyword_token

    def _process_str(self, str_input: list) -> Token:
        value = ""
        while True:
            if len(str_input) == 0:
                return Token(token_type=TokenType.STR, original_value=value)

            if "A" <= str_input[-1] <= "Z":  # We are in a string, but the next character indicates the start of a keyword
                return Token(token_type=TokenType.STR, original_value=value)

            match str_input[-1]:
                case "[" | "]" | "=" | ":" | "." | ">" | "<":
                    return Token(token_type=TokenType.STR, original_value=value)
                case _:
                    value += str_input.pop()

    def _match_keyword(self, str_input: str) -> Token | None:
        token = None
        match str_input:
            case "AND":
                token = Token(token_type=TokenType.AND, original_value=str_input)
            case "OR":
                token = Token(token_type=TokenType.OR, original_value=str_input)
            case "REPEATS":
                token = Token(token_type=TokenType.REPEATS, original_value=str_input)
            case "TIMES":
                token = Token(token_type=TokenType.TIMES, original_value=str_input)
            case "WITHIN":
                token = Token(token_type=TokenType.WITHIN, original_value=str_input)
            case "SECONDS":
                token = Token(token_type=TokenType.SECONDS, original_value=str_input)
            case "START":
                token = Token(token_type=TokenType.START, original_value=str_input)
            case "STOP":
                token = Token(token_type=TokenType.STOP, original_value=str_input)
            case "FOLLOWEDBY":
                token = Token(token_type=TokenType.FOLLOWEDBY, original_value=str_input)
            case "MATCHES":
                token = Token(token_type=TokenType.MATCHES, original_value=str_input)
            case "IN":
                token = Token(token_type=TokenType.IN, original_value=str_input)
            case "LIKE":
                token = Token(token_type=TokenType.LIKE, original_value=str_input)
            case "ISSUPERSET":
                token = Token(token_type=TokenType.ISSUPERSET, original_value=str_input)
            case "ISSUBSET":
                token = Token(token_type=TokenType.ISSUBSET, original_value=str_input)
        return token

    def _process_quoted_str(self, str_input: list) -> Token:
        str_input.pop()  # Read first quote
        value = ""
        while True:
            if len(str_input) == 0:
                msg = "Unexpected <EOD>"
                raise RuntimeError(msg)
            match str_input[-1]:
                case "'":
                    str_input.pop()
                    return Token(token_type=TokenType.QUOTED_STR, original_value=value)
                case _:
                    value += str_input.pop()


@dataclass
class ASTNode:
    pass


@dataclass
class ExpressionNode:
    left: ASTNode
    right: ASTNode
    operator: TokenType


@dataclass
class ObjectPathNode:
    object_type: str
    path: str


@dataclass
class ValueNode:
    value: str


class Parser:
    def _process_object_value(self, tokens: list[Token]) -> ValueNode:
        if tokens[-1].token_type != TokenType.QUOTED_STR:
            msg = "Expected a quoted string"
            raise RuntimeError(msg)

        return ValueNode(tokens.pop().original_value)

    def _process_object_path(self, tokens: list[Token]) -> ObjectPathNode:
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
            if tokens[-1].token_type != TokenType.STR:
                msg = "Expected a string"
                raise RuntimeError(msg)
            value += f".{tokens.pop().original_value}"

        return ObjectPathNode(object_type=object_type, path=value)

    def _process_expression(self, tokens: list[Token]) -> None:
        left = self._process_object_path(tokens)

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
                | TokenType.WITHIN
            ):
                pass
            case TokenType.NOT_EQUALS:
                pass
            case _:
                msg = "Expected a comparison operator"
                raise RuntimeError(msg)

        operator = tokens.pop().token_type

        right = self._process_object_value(tokens)

        return ExpressionNode(left=left, operator=operator, right=right)

    def process(self, tokens: list[Token]) -> None:
        tokens.reverse()

        # Every pattern must start with an opening bracket
        if tokens[-1].token_type is not TokenType.OPEN_BRACKET:
            raise RuntimeError

        while True:
            match tokens[-1].token_type:
                case TokenType.OPEN_BRACKET:
                    tokens.pop()
                    return self._process_expression(tokens)
