"""Ephemeral structural authorization for source-informed HTTP navigation."""

# Local contract errors intentionally use direct, caller-facing messages.
# ruff: noqa: EM101, TRY003

from __future__ import annotations

import ast
import io
import re
import tokenize
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath

from ravage.agent_core.source_context import (
    MAX_SOURCE_CONTEXT_EXCERPT_LINES,
    MAX_SOURCE_CONTEXT_SEARCH_MATCHES,
    SOURCE_CONTEXT_OBSERVATION_SCHEMA,
    SOURCE_CONTEXT_PROVENANCE,
    SOURCE_CONTEXT_TRUST,
)
from ravage.repository_context import RepositoryContext

_MAX_NAVIGATION_ROUTES = 4_096
_MAX_NAVIGATION_QUERY_FACTS = 4_096
_MAX_TOKENS_PER_FILE = 262_144
_MAX_BINDINGS_PER_FILE = 256
_MAX_ROUTE_CHARS = 1_024
_MAX_QUERY_NAME_CHARS = 128
_MAX_QUERY_FIELDS = 16
_MAX_REQUIRED_LINES = 32
_ASCII_CONTROL_BOUND = 32
_SCRIPT_SUFFIXES = frozenset({".cjs", ".js", ".jsx", ".mjs", ".ts", ".tsx"})
_NON_RUNTIME_COMPONENTS = frozenset(
    {
        "doc",
        "docs",
        "documentation",
        "example",
        "examples",
        "fixture",
        "fixtures",
        "spec",
        "specs",
        "test",
        "tests",
    }
)
_ROUTE_RECEIVERS = frozenset(
    {"api", "app", "blueprint", "bp", "fastapi", "fastify", "router", "server"}
)
_QUERY_ROOTS = frozenset({"req", "request"})
_URL_PATH_RECEIVERS = frozenset(
    {"parsed_url", "parsedurl", "request_uri", "request_url", "requesturi", "requesturl", "url"}
)
_SAFE_QUERY_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:\[\]-]{0,127}$")


class _PolicyOverflowError(Exception):
    """A structural index exceeded a fail-closed resource bound."""


@dataclass(frozen=True, slots=True, repr=False)
class _QueryFact:
    name: str
    line: int
    token_index: int = -1


@dataclass(frozen=True, slots=True, repr=False)
class _RouteFact:
    method: str
    path: str
    source_file: str
    required_lines: frozenset[int]
    query_facts: tuple[_QueryFact, ...] = ()


@dataclass(frozen=True, slots=True, repr=False)
class _Token:
    kind: str
    value: str
    line: int


@dataclass(frozen=True, slots=True, repr=False)
class _Binding:
    name: str
    path: str
    required_lines: frozenset[int]


@dataclass(frozen=True, slots=True, repr=False)
class SourceNavigationPolicy:
    """Exact route facts derived from one immutable repository snapshot."""

    _snapshot_id: str
    _facts: tuple[_RouteFact, ...]

    @property
    def route_count(self) -> int:
        return len({(fact.method, fact.path) for fact in self._facts})

    @property
    def query_name_count(self) -> int:
        return len({query.name for fact in self._facts for query in fact.query_facts})

    def permits_http_action(
        self,
        action: Mapping[str, object],
        *,
        observation: Mapping[str, object],
    ) -> bool:
        """Allow an exact route only when its structural lines were just observed."""
        if not isinstance(action, Mapping) or "url" in action:
            return False
        method = str(action.get("method") or "GET").upper()
        if method not in {"GET", "HEAD", "OPTIONS"}:
            return False
        parsed = _parse_relative_location(action.get("path"))
        if parsed is None:
            return False
        path, query_names = parsed
        visible = _visible_lines(observation, snapshot_id=self._snapshot_id)
        if not visible:
            return False
        for fact in self._facts:
            if fact.method != method or fact.path != path:
                continue
            file_lines = visible.get(fact.source_file, frozenset())
            if not fact.required_lines.issubset(file_lines):
                continue
            if all(
                any(query.name == name and query.line in file_lines for query in fact.query_facts)
                for name in query_names
            ):
                return True
        return False


def build_source_navigation_policy(
    context: RepositoryContext,
    *,
    candidate_payloads: Sequence[Mapping[str, object]] = (),
) -> SourceNavigationPolicy:
    """Build a bounded in-memory route index from captured source bytes."""
    if not isinstance(context, RepositoryContext):
        raise TypeError("context must be a RepositoryContext")
    # Candidate payloads intentionally grant no authority. Every permitted
    # request must be independently recoverable from exact source structure.
    _ = candidate_payloads
    facts: list[_RouteFact] = []
    query_fact_count = 0
    try:
        for source in context.files:
            path = PurePosixPath(source.path)
            if _non_runtime_path(path):
                continue
            suffix = path.suffix.casefold()
            if suffix == ".py":
                extracted = _python_route_facts(source.path, source.text)
            elif suffix in _SCRIPT_SUFFIXES:
                extracted = _script_route_facts(source.path, source.text)
            else:
                continue
            facts.extend(extracted)
            query_fact_count += sum(len(fact.query_facts) for fact in extracted)
            if (
                len(facts) > _MAX_NAVIGATION_ROUTES
                or query_fact_count > _MAX_NAVIGATION_QUERY_FACTS
            ):
                raise _PolicyOverflowError  # noqa: TRY301
    except _PolicyOverflowError:
        return SourceNavigationPolicy(context.snapshot_id, ())
    ordered = tuple(
        sorted(
            set(facts),
            key=lambda fact: (
                fact.source_file,
                min(fact.required_lines),
                fact.method,
                fact.path,
            ),
        )
    )
    return SourceNavigationPolicy(context.snapshot_id, ordered)


def _non_runtime_path(path: PurePosixPath) -> bool:
    lowered_parts = {part.casefold() for part in path.parts[:-1]}
    name = path.name.casefold()
    stem = path.stem.casefold()
    return bool(
        lowered_parts & _NON_RUNTIME_COMPONENTS
        or stem.endswith((".test", ".spec", "_test"))
        or name.startswith("test_")
    )


def _python_route_facts(source_file: str, text: str) -> list[_RouteFact]:
    try:
        token_count = sum(1 for _token in tokenize.generate_tokens(io.StringIO(text).readline))
        if token_count > _MAX_TOKENS_PER_FILE:
            raise _PolicyOverflowError  # noqa: TRY301
        tree = ast.parse(text)
    except _PolicyOverflowError:
        raise
    except (IndentationError, MemoryError, SyntaxError, tokenize.TokenError, ValueError):
        return []
    facts: list[_RouteFact] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        queries = _python_query_facts(node)
        for decorator in node.decorator_list:
            route = _python_decorator_route(decorator)
            if route is None:
                continue
            methods, path, lines = route
            facts.extend(
                _RouteFact(
                    method=method,
                    path=path,
                    source_file=source_file,
                    required_lines=lines,
                    query_facts=queries,
                )
                for method in methods
            )
    return facts


def _python_decorator_route(  # noqa: PLR0911
    decorator: ast.expr,
) -> tuple[frozenset[str], str, frozenset[int]] | None:
    if not isinstance(decorator, ast.Call) or not decorator.args:
        return None
    receiver, operation = _python_attribute_parts(decorator.func)
    if operation not in {"api_route", "get", "head", "options", "route"}:
        return None
    if not any(part.casefold() in _ROUTE_RECEIVERS for part in receiver):
        return None
    literal = decorator.args[0]
    if not isinstance(literal, ast.Constant) or not isinstance(literal.value, str):
        return None
    path = _safe_route(literal.value)
    if not path:
        return None
    methods = _python_route_methods(decorator, operation=operation)
    if not methods:
        return None
    lines = _node_lines(decorator)
    if not lines:
        return None
    return methods, path, lines


def _python_attribute_parts(node: ast.expr) -> tuple[tuple[str, ...], str]:
    if not isinstance(node, ast.Attribute):
        return (), ""
    parts = [node.attr]
    current: ast.expr = node.value
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    parts.reverse()
    return tuple(parts[:-1]), parts[-1] if parts else ""


def _python_route_methods(decorator: ast.Call, *, operation: str) -> frozenset[str]:
    if operation in {"get", "head", "options"}:
        return frozenset({operation.upper()})
    methods_keyword = next(
        (keyword.value for keyword in decorator.keywords if keyword.arg == "methods"),
        None,
    )
    if methods_keyword is None:
        return frozenset({"GET"})
    if not isinstance(methods_keyword, (ast.List, ast.Set, ast.Tuple)):
        return frozenset()
    methods = {
        item.value.upper()
        for item in methods_keyword.elts
        if isinstance(item, ast.Constant)
        and isinstance(item.value, str)
        and item.value.upper() in {"GET", "HEAD", "OPTIONS"}
    }
    return frozenset(methods)


def _python_query_facts(function: ast.AsyncFunctionDef | ast.FunctionDef) -> tuple[_QueryFact, ...]:
    found: set[_QueryFact] = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Call) and node.args and isinstance(node.func, ast.Attribute):
            if node.func.attr not in {"get", "has"}:
                continue
            if not _python_query_container(node.func.value):
                continue
            name = _python_string(node.args[0])
            if name and _safe_query_name(name):
                found.add(_QueryFact(name=name, line=node.lineno))
        elif isinstance(node, ast.Subscript) and _python_query_container(node.value):
            name = _python_string(node.slice)
            if name and _safe_query_name(name):
                found.add(_QueryFact(name=name, line=node.lineno))
    return tuple(sorted(found, key=lambda fact: (fact.line, fact.name)))


def _python_query_container(node: ast.expr) -> bool:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr.casefold())
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id.casefold())
    parts.reverse()
    return bool(
        parts
        and parts[0] in _QUERY_ROOTS
        and tuple(parts[1:]) in {("args",), ("query",), ("query_params",)}
    )


def _python_string(node: ast.expr) -> str:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


def _node_lines(node: ast.AST) -> frozenset[int]:
    start = getattr(node, "lineno", 0)
    end = getattr(node, "end_lineno", start)
    if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start:
        return frozenset()
    if end - start + 1 > _MAX_REQUIRED_LINES:
        return frozenset()
    return frozenset(range(start, end + 1))


def _script_route_facts(source_file: str, text: str) -> list[_RouteFact]:
    tokens = _script_tokens(text)
    if tokens is None:
        return []
    if len(tokens) > _MAX_TOKENS_PER_FILE:
        raise _PolicyOverflowError
    bindings = _script_bindings(tokens)
    queries = _script_query_facts(tokens)
    facts = _script_registered_routes(source_file, tokens, bindings, queries)
    facts.extend(_script_pathname_routes(source_file, tokens, bindings, queries))
    return facts


def _script_tokens(text: str) -> list[_Token] | None:  # noqa: C901, PLR0912, PLR0915
    tokens: list[_Token] = []
    index = 0
    line = 1
    length = len(text)
    while index < length:
        character = text[index]
        if character in " \t\r\f\v":
            index += 1
            continue
        if character == "\n":
            line += 1
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = length if newline < 0 else newline
            continue
        if text.startswith("/*", index):
            close = text.find("*/", index + 2)
            if close < 0:
                return None
            line += text.count("\n", index, close + 2)
            index = close + 2
            continue
        if character in {'"', "'", "`"}:
            quote = character
            start_line = line
            index += 1
            value: list[str] = []
            valid = True
            closed = False
            while index < length:
                current = text[index]
                if current == "\n":
                    valid = False
                    line += 1
                    index += 1
                    if quote != "`":
                        break
                    value.append("\n")
                    continue
                if current == "\\":
                    valid = False
                    index += 2
                    continue
                if quote == "`" and text.startswith("${", index):
                    valid = False
                if current == quote:
                    index += 1
                    closed = True
                    break
                value.append(current)
                index += 1
            if not closed:
                return None
            tokens.append(
                _Token("string" if valid else "invalid_string", "".join(value), start_line)
            )
        elif character.isalpha() or character in "_$":
            end = index + 1
            while end < length and (text[end].isalnum() or text[end] in "_$"):
                end += 1
            tokens.append(_Token("identifier", text[index:end], line))
            index = end
        else:
            operator = next(
                (
                    candidate
                    for candidate in ("===", "!==", "==", "!=", "+=", "-=", "=>")
                    if text.startswith(candidate, index)
                ),
                character,
            )
            tokens.append(_Token("symbol", operator, line))
            index += len(operator)
        if len(tokens) > _MAX_TOKENS_PER_FILE:
            raise _PolicyOverflowError
    return tokens


def _script_bindings(tokens: Sequence[_Token]) -> dict[str, _Binding]:
    bindings: dict[str, _Binding] = {}
    for index, token in enumerate(tokens):
        if token.kind != "identifier" or token.value != "const":
            continue
        if index + 1 >= len(tokens) or tokens[index + 1].kind != "identifier":
            continue
        name_token = tokens[index + 1]
        equals = _script_binding_equals(tokens, index + 2)
        if equals is None or equals + 1 >= len(tokens):
            continue
        literal = tokens[equals + 1]
        path = _safe_route(literal.value) if literal.kind == "string" else ""
        terminator = tokens[equals + 2].value if equals + 2 < len(tokens) else ";"
        if (
            not path
            or terminator != ";"
            or _identifier_reassigned(tokens, name_token.value, after=equals + 1)
        ):
            continue
        lines = frozenset(range(token.line, literal.line + 1))
        if not lines or len(lines) > _MAX_REQUIRED_LINES:
            continue
        bindings[name_token.value] = _Binding(name_token.value, path, lines)
        if len(bindings) > _MAX_BINDINGS_PER_FILE:
            raise _PolicyOverflowError
    return bindings


def _script_binding_equals(
    tokens: Sequence[_Token], start: int
) -> int | None:
    if start < len(tokens) and tokens[start].value == "=":
        return start
    if (
        start + 2 < len(tokens)
        and tokens[start].value == ":"
        and tokens[start + 1].kind == "identifier"
        and tokens[start + 1].value in {"String", "string"}
        and tokens[start + 2].value == "="
    ):
        return start + 2
    return None


def _identifier_reassigned(tokens: Sequence[_Token], name: str, *, after: int) -> bool:
    for index in range(after + 1, len(tokens) - 1):
        if tokens[index].kind != "identifier" or tokens[index].value != name:
            continue
        if tokens[index + 1].value in {"=", "+=", "-="}:
            return True
    return False


def _script_registered_routes(
    source_file: str,
    tokens: Sequence[_Token],
    bindings: Mapping[str, _Binding],
    queries: tuple[_QueryFact, ...],
) -> list[_RouteFact]:
    facts: list[_RouteFact] = []
    for index in range(len(tokens) - 5):
        receiver = tokens[index]
        dot = tokens[index + 1]
        method_token = tokens[index + 2]
        opening = tokens[index + 3]
        argument = tokens[index + 4]
        comma = tokens[index + 5]
        method = method_token.value.upper()
        if (
            receiver.kind != "identifier"
            or receiver.value.casefold() not in _ROUTE_RECEIVERS
            or dot.value != "."
            or method not in {"GET", "HEAD", "OPTIONS"}
            or opening.value != "("
            or comma.value != ","
        ):
            continue
        required = frozenset(range(receiver.line, comma.line + 1))
        path = _safe_route(argument.value) if argument.kind == "string" else ""
        if argument.kind == "identifier" and argument.value in bindings:
            binding = bindings[argument.value]
            path = binding.path
            required = required | binding.required_lines
        if not path or len(required) > _MAX_REQUIRED_LINES:
            continue
        facts.append(
            _RouteFact(
                method,
                path,
                source_file,
                required,
                _queries_in_call(tokens, index + 3, queries),
            )
        )
    return facts


def _queries_in_call(
    tokens: Sequence[_Token], opening: int, queries: tuple[_QueryFact, ...]
) -> tuple[_QueryFact, ...]:
    closing = _matching_symbol(tokens, opening, "(", ")")
    if closing is None:
        return ()
    return tuple(query for query in queries if opening <= query.token_index <= closing)


def _script_pathname_routes(
    source_file: str,
    tokens: Sequence[_Token],
    bindings: Mapping[str, _Binding],
    queries: tuple[_QueryFact, ...],
) -> list[_RouteFact]:
    facts: list[_RouteFact] = []
    for index in range(len(tokens) - 4):
        route_argument: _Token | None = None
        use_lines: set[int] = set()
        if (
            tokens[index].kind == "identifier"
            and tokens[index + 1].value == "."
            and _request_path_access(tokens[index].value, tokens[index + 2].value)
            and tokens[index + 3].value in {"==", "==="}
        ):
            route_argument = tokens[index + 4]
            use_lines.update(token.line for token in tokens[index : index + 5])
        elif (
            tokens[index].kind in {"identifier", "string"}
            and tokens[index + 1].value in {"==", "==="}
            and tokens[index + 2].kind == "identifier"
            and tokens[index + 3].value == "."
            and _request_path_access(tokens[index + 2].value, tokens[index + 4].value)
        ):
            route_argument = tokens[index]
            use_lines.update(token.line for token in tokens[index : index + 5])
        if route_argument is None:
            continue
        method_lines = _nearby_get_method_lines(tokens, index)
        if not method_lines:
            continue
        required = frozenset(use_lines | method_lines)
        path = _safe_route(route_argument.value) if route_argument.kind == "string" else ""
        if route_argument.kind == "identifier" and route_argument.value in bindings:
            binding = bindings[route_argument.value]
            path = binding.path
            required = required | binding.required_lines
        if not path or len(required) > _MAX_REQUIRED_LINES:
            continue
        facts.append(
            _RouteFact(
                "GET",
                path,
                source_file,
                required,
                _queries_in_if_branch(tokens, index, queries),
            )
        )
    return facts


def _request_path_access(receiver: str, attribute: str) -> bool:
    lowered = receiver.casefold()
    return (attribute == "pathname" and lowered in _URL_PATH_RECEIVERS) or (
        attribute == "path" and lowered in _QUERY_ROOTS
    )


def _queries_in_if_branch(
    tokens: Sequence[_Token],
    route_index: int,
    queries: tuple[_QueryFact, ...],
) -> tuple[_QueryFact, ...]:
    condition = _enclosing_if_condition(tokens, route_index)
    if condition is None:
        return ()
    start, closing = condition
    end = closing
    block_opening = closing + 1
    if block_opening < len(tokens) and tokens[block_opening].value == "{":
        block_closing = _matching_symbol(tokens, block_opening, "{", "}")
        if block_closing is not None:
            end = block_closing
    return tuple(query for query in queries if start <= query.token_index <= end)


def _nearby_get_method_lines(tokens: Sequence[_Token], route_index: int) -> set[int]:
    condition = _enclosing_if_condition(tokens, route_index)
    if condition is None:
        return set()
    start, end = condition
    for index in range(start, end):
        if index + 4 >= end:
            break
        direct = tokens[index : index + 5]
        if (
            direct[0].kind == "identifier"
            and direct[0].value.casefold() in _QUERY_ROOTS
            and direct[1].value == "."
            and direct[2].value == "method"
            and direct[3].value in {"==", "==="}
            and direct[4].kind == "string"
            and direct[4].value.upper() == "GET"
        ):
            return {token.line for token in direct}
    return set()


def _enclosing_if_condition(
    tokens: Sequence[_Token], route_index: int
) -> tuple[int, int] | None:
    for index in range(route_index - 1, max(-1, route_index - 80), -1):
        if tokens[index].kind != "identifier" or tokens[index].value != "if":
            continue
        opening = index + 1
        if opening >= len(tokens) or tokens[opening].value != "(":
            continue
        closing = _matching_symbol(tokens, opening, "(", ")")
        if closing is not None and opening < route_index < closing:
            return opening + 1, closing
    return None


def _script_query_facts(tokens: Sequence[_Token]) -> tuple[_QueryFact, ...]:
    facts: set[_QueryFact] = set()
    for index in range(len(tokens) - 4):
        if (
            tokens[index].kind == "identifier"
            and tokens[index].value.casefold() in _QUERY_ROOTS
            and tokens[index + 1].value == "."
            and tokens[index + 2].value in {"query", "queryParams", "query_params"}
        ):
            if tokens[index + 3].value == "." and tokens[index + 4].kind == "identifier":
                name = tokens[index + 4].value
                if name not in {"get", "has"} and _safe_query_name(name):
                    facts.add(_QueryFact(name, tokens[index + 4].line, index + 4))
            if (
                index + 6 < len(tokens)
                and tokens[index + 3].value == "."
                and tokens[index + 4].value in {"get", "has"}
                and tokens[index + 5].value == "("
                and tokens[index + 6].kind == "string"
                and _safe_query_name(tokens[index + 6].value)
            ):
                facts.add(
                    _QueryFact(tokens[index + 6].value, tokens[index + 6].line, index + 6)
                )
            if (
                index + 5 < len(tokens)
                and tokens[index + 3].value == "["
                and tokens[index + 4].kind == "string"
                and tokens[index + 5].value == "]"
                and _safe_query_name(tokens[index + 4].value)
            ):
                facts.add(
                    _QueryFact(tokens[index + 4].value, tokens[index + 4].line, index + 4)
                )
    return tuple(sorted(facts, key=lambda fact: (fact.line, fact.name)))


def _matching_symbol(
    tokens: Sequence[_Token], opening: int, left: str, right: str
) -> int | None:
    depth = 0
    for index in range(opening, len(tokens)):
        if tokens[index].value == left:
            depth += 1
        elif tokens[index].value == right:
            depth -= 1
            if depth == 0:
                return index
    return None


def _visible_lines(  # noqa: PLR0911
    observation: Mapping[str, object], *, snapshot_id: str
) -> dict[str, frozenset[int]]:
    if (
        not isinstance(observation, Mapping)
        or observation.get("schema") != SOURCE_CONTEXT_OBSERVATION_SCHEMA
        or observation.get("snapshot_id") != snapshot_id
        or observation.get("trust") != SOURCE_CONTEXT_TRUST
        or observation.get("proof_eligible") is not False
    ):
        return {}
    provenance = observation.get("provenance")
    if (
        not isinstance(provenance, Mapping)
        or provenance.get("kind") != SOURCE_CONTEXT_PROVENANCE
        or provenance.get("snapshot_id") != snapshot_id
    ):
        return {}
    observation_type = observation.get("type")
    if observation_type == "excerpt":
        path = observation.get("path")
        start = observation.get("start_line")
        end = observation.get("end_line")
        if (
            not isinstance(path, str)
            or type(start) is not int
            or type(end) is not int
            or start < 1
            or end < start
            or end - start + 1 > MAX_SOURCE_CONTEXT_EXCERPT_LINES
        ):
            return {}
        return {path: frozenset(range(start, end + 1))}
    if observation_type == "search_results":
        matches = observation.get("matches")
        if not isinstance(matches, list) or len(matches) > MAX_SOURCE_CONTEXT_SEARCH_MATCHES:
            return {}
        visible: dict[str, set[int]] = {}
        for match in matches:
            if not isinstance(match, Mapping) or match.get("text_truncated") is not False:
                continue
            path = match.get("path")
            line = match.get("line")
            if isinstance(path, str) and type(line) is int and line > 0:
                visible.setdefault(path, set()).add(line)
        return {path: frozenset(lines) for path, lines in visible.items()}
    return {}


def _parse_relative_location(  # noqa: PLR0911
    value: object,
) -> tuple[str, tuple[str, ...]] | None:
    if not isinstance(value, str) or not value or value != value.strip() or "#" in value:
        return None
    path, separator, raw_query = value.partition("?")
    if not _safe_route(path):
        return None
    if not separator:
        return path, ()
    pieces = raw_query.split("&")
    if not raw_query or len(pieces) > _MAX_QUERY_FIELDS:
        return None
    names: list[str] = []
    for piece in pieces:
        if piece.count("=") != 1 or not piece.endswith("="):
            return None
        name = piece[:-1]
        if not _safe_query_name(name) or name in names:
            return None
        names.append(name)
    return path, tuple(names)


def _safe_route(value: object) -> str:
    if not isinstance(value, str):
        return ""
    if (
        not value.startswith("/")
        or value.startswith("//")
        or len(value) > _MAX_ROUTE_CHARS
        or any(character in value for character in "\\?#%{}<>:*[]")
        or "//" in value
        or any(part in {".", ".."} for part in value.split("/"))
        or any(
            character.isspace() or ord(character) < _ASCII_CONTROL_BOUND
            for character in value
        )
    ):
        return ""
    return value


def _safe_query_name(value: object) -> str:
    return (
        value
        if isinstance(value, str)
        and len(value) <= _MAX_QUERY_NAME_CHARS
        and _SAFE_QUERY_NAME_RE.fullmatch(value)
        else ""
    )


__all__ = ["SourceNavigationPolicy", "build_source_navigation_policy"]
