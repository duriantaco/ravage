"""Ephemeral structural authorization for source-informed HTTP navigation."""

# Local contract errors intentionally use direct, caller-facing messages.
# ruff: noqa: EM101, TRY003

from __future__ import annotations

import ast
import hashlib
import io
import re
import tokenize
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from types import MappingProxyType

from ravage.agent_core.source_context import (
    MAX_SOURCE_CONTEXT_EXCERPT_LINES,
    MAX_SOURCE_CONTEXT_FILE_PAGE,
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
_MAX_SCRIPT_NESTING = 32
_MAX_ACCUMULATED_OBSERVATIONS = 16
_MAX_ACCUMULATED_REQUIREMENT_ATOMS = 2_048
_MAX_PROMPT_NAVIGATION_ROUTES = 32
_MIN_ROUTE_ARGUMENTS = 2
_STATIC_SHORT_CIRCUIT_PREFIX_TOKENS = 2
_ASCII_CONTROL_BOUND = 32
_SCRIPT_SUFFIXES = frozenset({".cjs", ".cts", ".js", ".mjs", ".mts", ".ts"})
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
_PYTHON_FRAMEWORK_CONSTRUCTORS = frozenset(
    {
        ("fastapi", "APIRouter"),
        ("fastapi", "FastAPI"),
        ("flask", "Blueprint"),
        ("flask", "Flask"),
        ("quart", "Blueprint"),
        ("quart", "Quart"),
        ("sanic", "Blueprint"),
        ("sanic", "Sanic"),
    }
)
_SCRIPT_FACTORY_PACKAGES = frozenset({"express", "fastify"})
_SCRIPT_ROUTER_PACKAGES = frozenset({"@koa/router"})


class _PolicyOverflowError(Exception):
    """A structural index exceeded a fail-closed resource bound."""


@dataclass(frozen=True, slots=True, repr=False)
class _QueryFact:
    name: str
    line: int
    token_index: int = -1
    root: str = ""


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
    declaration_index: int
    scope: tuple[int, ...]


@dataclass(frozen=True, slots=True, repr=False)
class _ReceiverBinding:
    name: str
    required_lines: frozenset[int]
    declaration_index: int
    path_prefix: str = ""


@dataclass(frozen=True, slots=True, repr=False)
class _ConstructorAlias:
    kind: str
    required_lines: frozenset[int]
    declaration_index: int


@dataclass(frozen=True, slots=True, repr=False)
class _ServerCallback:
    body_start: int
    body_end: int
    request_name: str
    required_lines: frozenset[int]


@dataclass(frozen=True, slots=True, repr=False)
class SourceNavigationPolicy:
    """Exact route facts derived from one immutable repository snapshot."""

    _snapshot_id: str
    _facts: tuple[_RouteFact, ...]
    _line_atoms: Mapping[tuple[str, int], int]

    @property
    def route_count(self) -> int:
        return len({(fact.method, fact.path) for fact in self._facts})

    @property
    def query_name_count(self) -> int:
        return len({query.name for fact in self._facts for query in fact.query_facts})

    def authorized_http_routes(
        self,
        *,
        observation: Mapping[str, object],
    ) -> tuple[tuple[str, str], ...]:
        """Return a bounded set of exact routes authorized by this observation."""
        evidence = self.begin_evidence()
        return evidence.authorized_http_routes() if evidence.observe(observation) else ()

    def permits_http_action(
        self,
        action: Mapping[str, object],
        *,
        observation: Mapping[str, object],
    ) -> bool:
        """Allow an exact route only when its structural lines were just observed."""
        evidence = self.begin_evidence()
        return evidence.permits_http_action(action) if evidence.observe(observation) else False

    def begin_evidence(self, *, require_task: bool = False) -> SourceNavigationEvidence:
        """Create one bounded, ephemeral authorization session for consecutive reads."""
        return SourceNavigationEvidence(self, _require_task=require_task)

    def _authorized_facts(
        self,
        observed_atoms: frozenset[int] | set[int],
    ) -> tuple[_RouteFact, ...]:
        return tuple(
            fact
            for fact in self._facts
            if self._required_atoms(fact).issubset(observed_atoms)
        )

    def _required_atoms(self, fact: _RouteFact) -> frozenset[int]:
        return frozenset(
            self._line_atoms[(fact.source_file, line)] for line in fact.required_lines
        )

    def _query_atom(self, fact: _RouteFact, query: _QueryFact) -> int:
        return self._line_atoms[(fact.source_file, query.line)]


@dataclass(frozen=True, slots=True, repr=False)
class SourceNavigationEvidence:
    """Opaque, text-free route evidence accumulated across consecutive source reads."""

    _policy: SourceNavigationPolicy
    _require_task: bool = False
    _observed_atoms: frozenset[int] = field(default_factory=frozenset)
    _observation_count: int = 0
    _task_id: str = ""
    _poisoned: bool = False

    @property
    def observation_count(self) -> int:
        return self._observation_count

    def observe(
        self,
        observation: Mapping[str, object],
        *,
        task_id: str = "",
    ) -> bool:
        """Add only policy-relevant atoms from one trusted snapshot observation."""
        normalized_task_id = str(task_id or "").strip()
        if (
            self._poisoned
            or (self._require_task and not normalized_task_id)
        ):
            self._poison()
            return False
        if (
            self._require_task
            and self._observation_count
            and normalized_task_id != self._task_id
        ):
            self.clear()
        visible = _visible_lines(
            observation,
            snapshot_id=self._policy._snapshot_id,  # noqa: SLF001
        )
        if visible is None:
            self._poison()
            return False
        atoms = frozenset(
            atom
            for source_file, lines in visible.items()
            for line in lines
            if (atom := self._policy._line_atoms.get((source_file, line))) is not None  # noqa: SLF001
        )
        combined_atoms = self._observed_atoms | atoms
        if (
            self._observation_count >= _MAX_ACCUMULATED_OBSERVATIONS
            or len(combined_atoms) > _MAX_ACCUMULATED_REQUIREMENT_ATOMS
        ):
            self._poison()
            return False
        object.__setattr__(self, "_observation_count", self._observation_count + 1)
        object.__setattr__(self, "_observed_atoms", combined_atoms)
        if self._require_task:
            object.__setattr__(self, "_task_id", normalized_task_id)
        return True

    def authorized_http_routes(self) -> tuple[tuple[str, str], ...]:
        """Return exact routes whose complete requirements were observed in this session."""
        if self._poisoned:
            return ()
        routes = sorted(
            {
                (fact.method, fact.path)
                for fact in self._policy._authorized_facts(self._observed_atoms)  # noqa: SLF001
            }
        )
        return tuple(routes[:_MAX_PROMPT_NAVIGATION_ROUTES])

    def permits_http_action(self, action: Mapping[str, object]) -> bool:
        """Authorize one bounded request from accumulated structural evidence."""
        if (
            self._poisoned
            or not isinstance(action, Mapping)
            or "url" in action
            or not self.permits_source_informed_action(action)
        ):
            return False
        method = str(action.get("method") or "GET").upper()
        if method not in {"GET", "HEAD", "OPTIONS"}:
            return False
        parsed = _parse_relative_location(action.get("path"))
        if parsed is None:
            return False
        path, query_names = parsed
        for fact in self._policy._authorized_facts(self._observed_atoms):  # noqa: SLF001
            if fact.method != method or fact.path != path:
                continue
            if all(
                any(
                    query.name == name
                    and self._policy._query_atom(fact, query) in self._observed_atoms  # noqa: SLF001
                    for query in fact.query_facts
                )
                for name in query_names
            ):
                return True
        return False

    def permits_source_informed_action(self, action: Mapping[str, object]) -> bool:
        """Require a source-informed action to retain this session's task lineage."""
        if self._poisoned or not isinstance(action, Mapping):
            return False
        if not self._require_task:
            return True
        action_task_id = str(action.get("task_id") or "").strip()
        return bool(
            self._observation_count
            and self._task_id
            and action_task_id == self._task_id
        )

    def clear(self) -> None:
        """Consume all authority and make the session reusable for a new source chain."""
        object.__setattr__(self, "_observed_atoms", frozenset())
        object.__setattr__(self, "_observation_count", 0)
        object.__setattr__(self, "_task_id", "")
        object.__setattr__(self, "_poisoned", False)

    def _poison(self) -> None:
        object.__setattr__(self, "_observed_atoms", frozenset())
        object.__setattr__(self, "_observation_count", 0)
        object.__setattr__(self, "_task_id", "")
        object.__setattr__(self, "_poisoned", True)


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
        return SourceNavigationPolicy(context.snapshot_id, (), MappingProxyType({}))
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
    source_lines = sorted(
        {
            (fact.source_file, line)
            for fact in ordered
            for line in (
                *fact.required_lines,
                *(query.line for query in fact.query_facts),
            )
        }
    )
    line_atoms = {
        source_line: _requirement_atom(context.snapshot_id, *source_line)
        for source_line in source_lines
    }
    return SourceNavigationPolicy(
        context.snapshot_id,
        ordered,
        MappingProxyType(line_atoms),
    )


def _requirement_atom(snapshot_id: str, source_file: str, line: int) -> int:
    material = f"{snapshot_id}\0{source_file}\0{line}".encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:16])


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
    receiver_bindings = _python_receiver_bindings(tree)
    if not receiver_bindings:
        return []
    facts: list[_RouteFact] = []
    for node in _reachable_module_functions(tree.body):
        queries = _python_query_facts(node)
        for decorator in node.decorator_list:
            route = _python_decorator_route(decorator, receiver_bindings=receiver_bindings)
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


def _python_receiver_bindings(tree: ast.Module) -> dict[str, _ReceiverBinding]:
    constructor_aliases, module_aliases = _python_constructor_aliases(tree.body)
    module_stores = _module_scope_stores(tree)
    attribute_mutations = _python_module_attribute_mutations(tree)
    bindings: dict[str, _ReceiverBinding] = {}
    for statement in _reachable_module_statements(tree.body):
        assignment = _python_simple_assignment(statement)
        if assignment is None:
            continue
        name, value = assignment
        if module_stores.get(name, 0) != 1 or not isinstance(value, ast.Call):
            continue
        if _python_receiver_method_mutated(tree, name):
            continue
        constructor = _python_constructor_call(
            value.func,
            constructor_aliases=constructor_aliases,
            module_aliases=module_aliases,
            module_stores=module_stores,
            attribute_mutations=attribute_mutations,
        )
        if constructor is None:
            continue
        import_lines, canonical = constructor
        prefix = _python_static_route_prefix(value, canonical=canonical)
        if prefix is None:
            continue
        assignment_lines = _node_lines(statement)
        if max(import_lines) >= min(assignment_lines):
            continue
        lines = assignment_lines | import_lines
        if lines and len(lines) <= _MAX_REQUIRED_LINES:
            bindings[name] = _ReceiverBinding(
                name,
                lines,
                max(assignment_lines),
                prefix,
            )
    mounted = _python_mounted_receiver_names(tree)
    return {name: binding for name, binding in bindings.items() if name not in mounted}


def _python_mounted_receiver_names(tree: ast.Module) -> frozenset[str]:
    visitor = _PythonMountedReceiverVisitor()
    for statement in tree.body:
        visitor.visit(statement)
    return frozenset(visitor.names)


class _PythonMountedReceiverVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"blueprint", "include_router", "register_blueprint"}
            and node.args
            and isinstance(node.args[0], ast.Name)
        ):
            self.names.add(node.args[0].id)
        self.generic_visit(node)

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


def _python_constructor_aliases(
    statements: Sequence[ast.stmt],
) -> tuple[
    dict[str, tuple[tuple[str, str], frozenset[int]]],
    dict[str, tuple[str, frozenset[int]]],
]:
    constructors: dict[str, tuple[tuple[str, str], frozenset[int]]] = {}
    modules: dict[str, tuple[str, frozenset[int]]] = {}
    import_counts: dict[str, int] = {}
    for statement in statements:
        lines = _node_lines(statement)
        if isinstance(statement, ast.ImportFrom) and statement.module:
            for alias in statement.names:
                if alias.name == "*":
                    return {}, {}
                local_name = alias.asname or alias.name
                import_counts[local_name] = import_counts.get(local_name, 0) + 1
                canonical = (statement.module, alias.name)
                if canonical in _PYTHON_FRAMEWORK_CONSTRUCTORS:
                    constructors[local_name] = (canonical, lines)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                local_name = alias.asname or alias.name.split(".", maxsplit=1)[0]
                import_counts[local_name] = import_counts.get(local_name, 0) + 1
                if any(module == alias.name for module, _name in _PYTHON_FRAMEWORK_CONSTRUCTORS):
                    modules[local_name] = (alias.name, lines)
    constructors = {
        name: value for name, value in constructors.items() if import_counts.get(name) == 1
    }
    modules = {name: value for name, value in modules.items() if import_counts.get(name) == 1}
    return constructors, modules


def _python_static_route_prefix(
    call: ast.Call, *, canonical: tuple[str, str]
) -> str | None:
    prefix_names = {"prefix"} if canonical[1] == "APIRouter" else {"url_prefix"}
    for keyword in call.keywords:
        if keyword.arg not in prefix_names:
            continue
        if isinstance(keyword.value, ast.Constant) and keyword.value.value in {None, ""}:
            continue
        if not isinstance(keyword.value, ast.Constant) or not isinstance(
            keyword.value.value, str
        ):
            return None
        return _safe_route(keyword.value.value) or None
    return ""


def _python_receiver_method_mutated(tree: ast.Module, receiver: str) -> bool:
    visitor = _PythonMemberMutationVisitor(receiver)
    for statement in tree.body:
        visitor.visit(statement)
    return visitor.mutated


class _PythonMemberMutationVisitor(ast.NodeVisitor):
    def __init__(self, receiver: str) -> None:
        self.receiver = receiver
        self.mutated = False

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if (
            isinstance(node.ctx, (ast.Del, ast.Store))
            and isinstance(node.value, ast.Name)
            and node.value.id == self.receiver
            and node.attr in {"api_route", "get", "head", "options", "route"}
        ):
            self.mutated = True

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"delattr", "setattr"}
            and len(node.args) >= _MIN_ROUTE_ARGUMENTS
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == self.receiver
            and _python_string(node.args[1])
            in {"api_route", "get", "head", "options", "route"}
        ):
            self.mutated = True
        self.generic_visit(node)

def _python_constructor_call(
    function: ast.expr,
    *,
    constructor_aliases: Mapping[str, tuple[tuple[str, str], frozenset[int]]],
    module_aliases: Mapping[str, tuple[str, frozenset[int]]],
    module_stores: Mapping[str, int],
    attribute_mutations: frozenset[tuple[str, str]],
) -> tuple[frozenset[int], tuple[str, str]] | None:
    if isinstance(function, ast.Name):
        constructor = constructor_aliases.get(function.id)
        if constructor is not None and module_stores.get(function.id, 0) == 1:
            return constructor[1], constructor[0]
        return None
    if not (
        isinstance(function, ast.Attribute)
        and isinstance(function.value, ast.Name)
        and function.value.id in module_aliases
    ):
        return None
    module, lines = module_aliases[function.value.id]
    if (
        module_stores.get(function.value.id, 0) == 1
        and (function.value.id, function.attr) not in attribute_mutations
        and (module, function.attr) in _PYTHON_FRAMEWORK_CONSTRUCTORS
    ):
        return lines, (module, function.attr)
    return None


def _python_module_attribute_mutations(
    tree: ast.Module,
) -> frozenset[tuple[str, str]]:
    visitor = _PythonAttributeMutationCollector()
    for statement in tree.body:
        visitor.visit(statement)
    return frozenset(visitor.mutations)


class _PythonAttributeMutationCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.mutations: set[tuple[str, str]] = set()

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, (ast.Del, ast.Store)) and isinstance(node.value, ast.Name):
            self.mutations.add((node.value.id, node.attr))

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"delattr", "setattr"}
            and len(node.args) >= _MIN_ROUTE_ARGUMENTS
            and isinstance(node.args[0], ast.Name)
        ):
            attribute = _python_string(node.args[1])
            if attribute:
                self.mutations.add((node.args[0].id, attribute))
        self.generic_visit(node)

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


class _ModuleStoreVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Del, ast.Store)):
            self.counts[node.id] = self.counts.get(node.id, 0) + 1

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".", maxsplit=1)[0]
            self.counts[name] = self.counts.get(name, 0) + 1

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*":
                continue
            name = alias.asname or alias.name
            self.counts[name] = self.counts.get(name, 0) + 1

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.counts[node.name] = self.counts.get(node.name, 0) + 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.counts[node.name] = self.counts.get(node.name, 0) + 1

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.counts[node.name] = self.counts.get(node.name, 0) + 1

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


def _module_scope_stores(tree: ast.Module) -> dict[str, int]:
    visitor = _ModuleStoreVisitor()
    for statement in tree.body:
        visitor.visit(statement)
    return visitor.counts


def _reachable_module_statements(statements: Sequence[ast.stmt]) -> tuple[ast.stmt, ...]:
    reachable: list[ast.stmt] = []
    for statement in statements:
        reachable.append(statement)
        if isinstance(statement, ast.If):
            truth = _python_static_truth(statement.test)
            branch = statement.body if truth is True else statement.orelse
            if truth is None:
                reachable.extend(_reachable_module_statements(statement.body))
            reachable.extend(_reachable_module_statements(branch))
        elif isinstance(statement, (ast.Try, ast.TryStar)):
            reachable.extend(_reachable_module_statements(statement.body))
            reachable.extend(_reachable_module_statements(statement.orelse))
            reachable.extend(_reachable_module_statements(statement.finalbody))
            for handler in statement.handlers:
                reachable.extend(_reachable_module_statements(handler.body))
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            reachable.extend(_reachable_module_statements(statement.body))
    return tuple(reachable)


def _reachable_module_functions(
    statements: Sequence[ast.stmt],
) -> tuple[ast.AsyncFunctionDef | ast.FunctionDef, ...]:
    return tuple(
        statement
        for statement in _reachable_module_statements(statements)
        if isinstance(statement, (ast.AsyncFunctionDef, ast.FunctionDef))
    )


def _python_simple_assignment(statement: ast.stmt) -> tuple[str, ast.expr] | None:
    if (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
    ):
        return statement.targets[0].id, statement.value
    if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
        return (statement.target.id, statement.value) if statement.value is not None else None
    return None


def _python_decorator_route(  # noqa: PLR0911
    decorator: ast.expr,
    *,
    receiver_bindings: Mapping[str, _ReceiverBinding],
) -> tuple[frozenset[str], str, frozenset[int]] | None:
    if not isinstance(decorator, ast.Call) or len(decorator.args) != 1:
        return None
    receiver, operation = _python_attribute_parts(decorator.func)
    if operation not in {"api_route", "get", "head", "options", "route"}:
        return None
    if len(receiver) != 1 or receiver[0] not in receiver_bindings:
        return None
    binding = receiver_bindings[receiver[0]]
    decorator_lines = _node_lines(decorator)
    if not decorator_lines or binding.declaration_index >= min(decorator_lines):
        return None
    literal = decorator.args[0]
    if not isinstance(literal, ast.Constant) or not isinstance(literal.value, str):
        return None
    path = _safe_route(literal.value)
    if not path:
        return None
    path = _compose_static_route(binding.path_prefix, path)
    if not path:
        return None
    methods = _python_route_methods(decorator, operation=operation)
    if not methods:
        return None
    lines = decorator_lines | binding.required_lines
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
    visitor = _PythonQueryVisitor(_python_local_bindings(function))
    visitor.visit_block(function.body)
    return tuple(sorted(visitor.found, key=lambda fact: (fact.line, fact.name)))


class _PythonQueryVisitor(ast.NodeVisitor):
    def __init__(self, shadowed_roots: frozenset[str]) -> None:
        self.found: set[_QueryFact] = set()
        self.shadowed_roots = shadowed_roots

    def visit_block(self, statements: Sequence[ast.stmt]) -> None:
        for statement in statements:
            self.visit(statement)
            if isinstance(statement, (ast.Break, ast.Continue, ast.Raise, ast.Return)):
                break

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node, ast.Call) and node.args and isinstance(node.func, ast.Attribute):
            if node.func.attr not in {"get", "has"}:
                self.generic_visit(node)
                return
            if _python_query_container(
                node.func.value,
                shadowed_roots=self.shadowed_roots,
            ):
                name = _python_string(node.args[0])
                if name and _safe_query_name(name):
                    self.found.add(_QueryFact(name=name, line=node.lineno))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if _python_query_container(node.value, shadowed_roots=self.shadowed_roots):
            name = _python_string(node.slice)
            if name and _safe_query_name(name):
                self.found.add(_QueryFact(name=name, line=node.lineno))
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        truth = _python_static_truth(node.test)
        if truth is True:
            self.visit_block(node.body)
        elif truth is False:
            self.visit_block(node.orelse)
        else:
            self.visit(node.test)
            self.visit_block(node.body)
            self.visit_block(node.orelse)

    def visit_While(self, node: ast.While) -> None:
        if _python_static_truth(node.test) is False:
            self.visit_block(node.orelse)
            return
        self.generic_visit(node)

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


def _python_local_bindings(
    function: ast.AsyncFunctionDef | ast.FunctionDef,
) -> frozenset[str]:
    visitor = _PythonLocalBindingVisitor()
    arguments = (
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    )
    visitor.names.update(argument.arg for argument in arguments)
    if function.args.vararg is not None:
        visitor.names.add(function.args.vararg.arg)
    if function.args.kwarg is not None:
        visitor.names.add(function.args.kwarg.arg)
    for statement in function.body:
        visitor.visit(statement)
    return frozenset(visitor.names & _QUERY_ROOTS)


class _PythonLocalBindingVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Del, ast.Store)):
            self.names.add(node.id.casefold())

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.names.add((alias.asname or alias.name.split(".", maxsplit=1)[0]).casefold())

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                self.names.add((alias.asname or alias.name).casefold())

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name.casefold())

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.names.add(node.name.casefold())

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name.casefold())

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


def _python_static_truth(  # noqa: C901, PLR0911, PLR0912
    node: ast.expr,
) -> bool | None:
    if isinstance(node, ast.Constant):
        value = node.value
        if value is None or value is False:
            return False
        if type(value) in {complex, float, int} and not value:
            return False
        if isinstance(value, (bytes, str)) and not value:
            return False
        if value is True:
            return True
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)) and not node.elts:
        return False
    if isinstance(node, ast.Dict) and not node.keys:
        return False
    if isinstance(node, ast.Name) and node.id == "TYPE_CHECKING":
        return False
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "typing"
        and node.attr == "TYPE_CHECKING"
    ):
        return False
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        operand = _python_static_truth(node.operand)
        return None if operand is None else not operand
    if isinstance(node, ast.BoolOp):
        values = tuple(_python_static_truth(value) for value in node.values)
        if isinstance(node.op, ast.And):
            if False in values:
                return False
            return True if all(value is True for value in values) else None
        if True in values:
            return True
        return False if all(value is False for value in values) else None
    if (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and len(node.comparators) == 1
    ):
        left = _python_static_scalar(node.left)
        right = _python_static_scalar(node.comparators[0])
        if left is _UNKNOWN_STATIC_VALUE or right is _UNKNOWN_STATIC_VALUE:
            return None
        operation = node.ops[0]
        if isinstance(operation, (ast.Eq, ast.Is)):
            return left == right
        if isinstance(operation, (ast.IsNot, ast.NotEq)):
            return left != right
    return None


_UNKNOWN_STATIC_VALUE = object()


def _python_static_scalar(node: ast.expr) -> object:
    if isinstance(node, ast.Constant) and type(node.value) in {
        bool,
        bytes,
        complex,
        float,
        int,
        str,
        type(None),
    }:
        return node.value
    return _UNKNOWN_STATIC_VALUE


def _python_query_container(
    node: ast.expr, *, shadowed_roots: frozenset[str]
) -> bool:
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
        and parts[0] not in shadowed_roots
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
    if tokens is None or not _script_syntax_is_supported(tokens):
        return []
    if len(tokens) > _MAX_TOKENS_PER_FILE:
        raise _PolicyOverflowError
    scope_paths = _script_scope_paths(tokens)
    function_bodies = _script_function_body_ranges(tokens)
    bindings = _script_bindings(tokens, scope_paths=scope_paths)
    receiver_bindings = _script_receiver_bindings(tokens)
    server_callbacks = _script_server_callbacks(tokens, function_bodies=function_bodies)
    dead_ranges = _script_static_false_ranges(tokens)
    queries = _script_query_facts(tokens, dead_ranges=dead_ranges)
    facts = _script_registered_routes(
        source_file,
        tokens,
        bindings,
        receiver_bindings,
        queries,
        function_bodies=function_bodies,
        scope_paths=scope_paths,
        dead_ranges=dead_ranges,
    )
    facts.extend(
        _script_pathname_routes(
            source_file,
            tokens,
            bindings,
            queries,
            server_callbacks=server_callbacks,
            function_bodies=function_bodies,
            scope_paths=scope_paths,
            dead_ranges=dead_ranges,
        )
    )
    return facts


def _script_tokens(text: str) -> list[_Token] | None:  # noqa: C901, PLR0912, PLR0915
    tokens: list[_Token] = []
    index = 0
    line = 1
    length = len(text)
    while index < length:
        character = text[index]
        if index == 0 and text.startswith("#!", index):
            newline = text.find("\n", index + 2)
            index = length if newline < 0 else newline
            continue
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
        if text.startswith("<!--", index) or (
            _script_line_prefix_is_whitespace(text, index) and text.startswith("-->", index)
        ):
            newline = text.find("\n", index + 3)
            index = length if newline < 0 else newline
            continue
        if text.startswith("/*", index):
            close = text.find("*/", index + 2)
            if close < 0:
                return None
            line += text.count("\n", index, close + 2)
            index = close + 2
            continue
        if character == "/":
            return None
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
                    if index + 1 < length and text[index + 1] == "\n":
                        line += 1
                        index += 2
                    elif index + 2 < length and text[index + 1 : index + 3] == "\r\n":
                        line += 1
                        index += 3
                    else:
                        index += 2
                    continue
                if quote == "`" and text.startswith("${", index):
                    return None
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
                    for candidate in (
                        "===",
                        "!==",
                        "==",
                        "!=",
                        "+=",
                        "-=",
                        "++",
                        "--",
                        "&&",
                        "||",
                        "?.",
                        "=>",
                    )
                    if text.startswith(candidate, index)
                ),
                character,
            )
            tokens.append(_Token("symbol", operator, line))
            index += len(operator)
        if len(tokens) > _MAX_TOKENS_PER_FILE:
            raise _PolicyOverflowError
    return tokens


def _script_line_prefix_is_whitespace(text: str, index: int) -> bool:
    line_start = text.rfind("\n", 0, index) + 1
    return not text[line_start:index].strip()


def _script_syntax_is_supported(  # noqa: C901, PLR0911
    tokens: Sequence[_Token],
) -> bool:
    stack: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for token in tokens:
        if token.value in {"(", "[", "{"}:
            stack.append(token.value)
            if len(stack) > _MAX_SCRIPT_NESTING:
                return False
        elif token.value in pairs and (
            not stack or stack.pop() != pairs[token.value]
        ):
            return False
    if stack:
        return False
    for index, token in enumerate(tokens):
        if token.value in {"const", "let", "var"} and not _script_declaration_valid(
            tokens,
            index,
        ):
            return False
        if token.value in {"catch", "for", "if", "switch", "while", "with"} and (
            index + 1 >= len(tokens) or tokens[index + 1].value != "("
        ):
            return False
        if token.value == "=>" and (
            index + 1 >= len(tokens) or tokens[index + 1].value in {",", ";", ")", "]"}
        ):
            return False
        if token.value == "do" and _script_do_while_end(tokens, index) is None:
            return False
        if token.value == "throw" and (
            index + 1 >= len(tokens)
            or tokens[index + 1].line != token.line
            or tokens[index + 1].value in {";", "}"}
        ):
            return False
        if token.value == "(" and not _script_parenthesized_tokens_valid(tokens, index):
            return False
    return True


def _script_declaration_valid(tokens: Sequence[_Token], index: int) -> bool:
    if index + 1 >= len(tokens) or tokens[index + 1].kind != "identifier":
        return False
    offset = index + 2
    if offset < len(tokens) and tokens[offset].value == ":":
        offset += 1
        limit = min(len(tokens), offset + _MAX_REQUIRED_LINES)
        while offset < limit and tokens[offset].value not in {"=", ";"}:
            offset += 1
    if offset < len(tokens) and tokens[offset].value == "=":
        return offset + 1 < len(tokens) and tokens[offset + 1].value not in {
            ",",
            ";",
            ")",
            "]",
            "}",
        }
    if (
        offset < len(tokens)
        and tokens[offset].value in {"in", "of"}
        and _script_token_is_in_for_header(tokens, index)
    ):
        return offset + 1 < len(tokens) and tokens[offset + 1].value != ")"
    return tokens[index].value != "const"


def _script_token_is_in_for_header(tokens: Sequence[_Token], index: int) -> bool:
    depth = 0
    for offset in range(index - 1, -1, -1):
        value = tokens[offset].value
        if value == ")":
            depth += 1
        elif value == "(":
            if depth:
                depth -= 1
                continue
            return offset > 0 and tokens[offset - 1].value == "for"
    return False


def _script_parenthesized_tokens_valid(
    tokens: Sequence[_Token], opening: int
) -> bool:
    closing = _matching_symbol(tokens, opening, "(", ")")
    if closing is None:
        return False
    commas = _script_top_level_indices(
        tokens,
        start=opening + 1,
        end=closing,
        value=",",
    )
    if commas and commas[0] == opening + 1:
        return False
    if any(
        commas[index] + 1 == commas[index + 1]
        for index in range(len(commas) - 1)
    ):
        return False
    is_for_header = opening > 0 and tokens[opening - 1].value == "for"
    return is_for_header or not _script_top_level_indices(
        tokens,
        start=opening + 1,
        end=closing,
        value=";",
    )


def _script_top_level_indices(
    tokens: Sequence[_Token], *, start: int, end: int, value: str
) -> tuple[int, ...]:
    depths = {"(": 0, "[": 0, "{": 0}
    closing_to_opening = {")": "(", "]": "[", "}": "{"}
    found: list[int] = []
    for index in range(start, end):
        current = tokens[index].value
        if current in depths:
            depths[current] += 1
        elif current in closing_to_opening:
            opening = closing_to_opening[current]
            depths[opening] = max(0, depths[opening] - 1)
        elif current == value and not any(depths.values()):
            found.append(index)
    return tuple(found)


def _script_do_while_end(  # noqa: PLR0911
    tokens: Sequence[_Token], do_index: int
) -> int | None:
    body_start = do_index + 1
    if body_start >= len(tokens):
        return None
    if tokens[body_start].value == "{":
        body_end = _matching_symbol(tokens, body_start, "{", "}")
    else:
        body_end = _script_statement_end(tokens, body_start)
    if body_end is None:
        return None
    tail = body_end + 1
    if tail >= len(tokens) or tokens[tail].value != "while":
        return None
    if tail + 1 >= len(tokens) or tokens[tail + 1].value != "(":
        return None
    condition_end = _matching_symbol(tokens, tail + 1, "(", ")")
    if condition_end is None:
        return None
    end = condition_end + 1
    if end < len(tokens) and tokens[end].value == ";":
        return end
    return condition_end if end == len(tokens) else None


def _script_bindings(
    tokens: Sequence[_Token], *, scope_paths: Sequence[tuple[int, ...]]
) -> dict[str, _Binding]:
    candidates: dict[str, list[_Binding]] = {}
    declaration_counts = _script_declaration_counts(tokens)
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
        if (
            not path
            or not _script_declaration_ends(tokens, equals + 1)
            or _identifier_reassigned(tokens, name_token.value, after=equals + 1)
        ):
            continue
        lines = frozenset(range(token.line, literal.line + 1))
        if not lines or len(lines) > _MAX_REQUIRED_LINES:
            continue
        candidates.setdefault(name_token.value, []).append(
            _Binding(
                name_token.value,
                path,
                lines,
                index + 1,
                scope_paths[index],
            )
        )
        if len(candidates) > _MAX_BINDINGS_PER_FILE:
            raise _PolicyOverflowError
    return {
        name: items[0]
        for name, items in candidates.items()
        if len(items) == 1 and declaration_counts.get(name) == 1
    }


def _script_declaration_counts(tokens: Sequence[_Token]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for index in range(len(tokens) - 1):
        if tokens[index].value not in {"class", "const", "function", "let", "var"}:
            continue
        name = tokens[index + 1]
        if name.kind == "identifier":
            counts[name.value] = counts.get(name.value, 0) + 1
    return counts


def _visible_script_binding(
    bindings: Mapping[str, _Binding],
    name: str,
    *,
    use_index: int,
    scope_paths: Sequence[tuple[int, ...]],
) -> _Binding | None:
    binding = bindings.get(name)
    if binding is None or binding.declaration_index >= use_index:
        return None
    use_scope = scope_paths[use_index]
    if use_scope[: len(binding.scope)] != binding.scope:
        return None
    return binding


def _script_binding_equals(
    tokens: Sequence[_Token], start: int
) -> int | None:
    if start < len(tokens) and tokens[start].value == "=":
        return start
    if (
        start + 2 < len(tokens)
        and tokens[start].value == ":"
        and tokens[start + 1].kind == "identifier"
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


def _script_receiver_bindings(tokens: Sequence[_Token]) -> dict[str, _ReceiverBinding]:
    depths = _script_brace_depths(tokens)
    aliases = _script_constructor_aliases(tokens, depths=depths)
    require_shadowed = _script_require_shadowed(tokens)
    candidates: dict[str, list[_ReceiverBinding]] = {}
    for index in range(len(tokens) - 4):
        if (
            depths[index] != 0
            or tokens[index].value != "const"
            or tokens[index + 1].kind != "identifier"
        ):
            continue
        equals = _script_binding_equals(tokens, index + 2)
        if equals is None:
            continue
        expression_start = equals + 1
        expression_end = _script_constructor_expression_end(
            tokens,
            expression_start,
            aliases=aliases,
        )
        if expression_end is None or not _script_declaration_ends(tokens, expression_end):
            continue
        constructor_lines = _script_constructor_expression_lines(
            tokens,
            expression_start,
            expression_end + 1,
            aliases=aliases,
            require_shadowed=require_shadowed,
        )
        if not constructor_lines:
            continue
        name = tokens[index + 1].value
        lines = frozenset(
            {token.line for token in tokens[index : expression_end + 1]}
            | set(constructor_lines)
        )
        if len(lines) > _MAX_REQUIRED_LINES:
            continue
        candidates.setdefault(name, []).append(_ReceiverBinding(name, lines, index + 1))
    bindings: dict[str, _ReceiverBinding] = {}
    for name, matches in candidates.items():
        if len(matches) != 1:
            continue
        match = matches[0]
        if not _script_receiver_rebound(tokens, name, declaration_index=match.declaration_index):
            bindings[name] = match
    mounted = _script_mounted_receiver_names(tokens)
    return {name: binding for name, binding in bindings.items() if name not in mounted}


def _script_mounted_receiver_names(tokens: Sequence[_Token]) -> frozenset[str]:
    mounted: set[str] = set()
    for index in range(len(tokens) - 7):
        if (
            tokens[index].kind != "identifier"
            or tokens[index + 1].value != "."
            or tokens[index + 2].value != "use"
            or tokens[index + 3].value != "("
            or tokens[index + 4].kind != "string"
            or not _safe_route(tokens[index + 4].value)
            or tokens[index + 5].value != ","
            or tokens[index + 6].kind != "identifier"
        ):
            continue
        closing = _matching_symbol(tokens, index + 3, "(", ")")
        if closing is not None and closing > index + 6:
            mounted.add(tokens[index + 6].value)
    return frozenset(mounted)


def _script_constructor_aliases(
    tokens: Sequence[_Token], *, depths: Sequence[int]
) -> dict[str, _ConstructorAlias]:
    aliases: dict[str, _ConstructorAlias] = {}
    require_shadowed = _script_require_shadowed(tokens)
    for index in range(len(tokens) - 7):
        if depths[index] != 0:
            continue
        commonjs = _commonjs_constructor_alias(
            tokens,
            index,
            require_shadowed=require_shadowed,
        )
        if commonjs is not None:
            name, kind, end = commonjs
            aliases[name] = _ConstructorAlias(
                kind,
                frozenset(token.line for token in tokens[index : end + 1]),
                index + 1,
            )
            continue
        imported = _module_constructor_alias(tokens, index)
        if imported is not None:
            name, kind, end = imported
            aliases[name] = _ConstructorAlias(
                kind,
                frozenset(token.line for token in tokens[index : end + 1]),
                index + (2 if tokens[index + 1].value == "{" else 1),
            )
    return aliases


def _commonjs_constructor_alias(
    tokens: Sequence[_Token], index: int, *, require_shadowed: bool
) -> tuple[str, str, int] | None:
    if (
        require_shadowed
        or
        tokens[index].value != "const"
        or tokens[index + 1].kind != "identifier"
        or tokens[index + 2].value != "="
        or tokens[index + 3].value != "require"
        or tokens[index + 4].value != "("
        or tokens[index + 5].kind != "string"
        or tokens[index + 6].value != ")"
        or not _script_declaration_ends(tokens, index + 6)
    ):
        return None
    package = tokens[index + 5].value
    if package in _SCRIPT_FACTORY_PACKAGES:
        return tokens[index + 1].value, "factory", index + 6
    if package in _SCRIPT_ROUTER_PACKAGES:
        return tokens[index + 1].value, "router", index + 6
    return None


def _module_constructor_alias(
    tokens: Sequence[_Token], index: int
) -> tuple[str, str, int] | None:
    if (
        tokens[index].value == "import"
        and tokens[index + 1].kind == "identifier"
        and tokens[index + 2].value == "from"
        and tokens[index + 3].kind == "string"
        and _script_declaration_ends(tokens, index + 3)
    ):
        package = tokens[index + 3].value
        if package in _SCRIPT_FACTORY_PACKAGES:
            return tokens[index + 1].value, "factory", index + 3
        if package in _SCRIPT_ROUTER_PACKAGES:
            return tokens[index + 1].value, "router", index + 3
    if not (
        tokens[index].value == "import"
        and tokens[index + 1].value == "{"
        and tokens[index + 2].kind == "identifier"
        and tokens[index + 3].value == "}"
        and tokens[index + 4].value == "from"
        and tokens[index + 5].kind == "string"
        and _script_declaration_ends(tokens, index + 5)
    ):
        return None
    if tokens[index + 2].value == "Router" and tokens[index + 5].value == "express":
        return "Router", "router", index + 5
    return None


def _script_constructor_expression_lines(
    tokens: Sequence[_Token],
    start: int,
    end: int,
    *,
    aliases: Mapping[str, _ConstructorAlias],
    require_shadowed: bool,
) -> frozenset[int]:
    if start >= end:
        return frozenset()
    offset = start
    used_alias: _ConstructorAlias | None = None
    if tokens[offset].value == "new":
        offset += 1
    if offset < end and tokens[offset].kind == "identifier":
        used_alias = aliases.get(tokens[offset].value)
        call_opening = offset + 1
        if (
            used_alias is not None
            and used_alias.kind == "factory"
            and call_opening + 2 < end
            and tokens[call_opening].value == "."
            and tokens[call_opening + 1].value == "Router"
        ):
            call_opening += 2
            used_alias = _ConstructorAlias(
                "router",
                used_alias.required_lines,
                used_alias.declaration_index,
            )
        if (
            used_alias is not None
            and used_alias.declaration_index < offset
            and not _script_receiver_rebound(
                tokens,
                tokens[offset].value,
                declaration_index=used_alias.declaration_index,
            )
            and tokens[call_opening].value == "("
            and _matching_symbol(tokens, call_opening, "(", ")") == end - 1
            and not _script_route_method_mutated(
                tokens,
                tokens[offset].value,
                "Router",
                before=offset,
            )
        ):
            return used_alias.required_lines
    direct_package = _direct_require_factory_package(
        tokens,
        offset,
        end,
        require_shadowed=require_shadowed,
    )
    if direct_package in _SCRIPT_FACTORY_PACKAGES | _SCRIPT_ROUTER_PACKAGES:
        return frozenset(token.line for token in tokens[offset:end])
    return frozenset()


def _direct_require_factory_package(
    tokens: Sequence[_Token], start: int, end: int, *, require_shadowed: bool
) -> str:
    if (
        require_shadowed
        or
        start + 5 >= end
        or tokens[start].value != "require"
        or tokens[start + 1].value != "("
        or tokens[start + 2].kind != "string"
        or tokens[start + 3].value != ")"
        or tokens[start + 4].value != "("
        or _matching_symbol(tokens, start + 4, "(", ")") != end - 1
    ):
        return ""
    return tokens[start + 2].value


def _script_require_shadowed(tokens: Sequence[_Token]) -> bool:
    for index, token in enumerate(tokens):
        if token.value != "require":
            continue
        previous = tokens[index - 1].value if index else ""
        following = tokens[index + 1].value if index + 1 < len(tokens) else ""
        if previous in {"class", "const", "function", "import", "let", "var"}:
            return True
        if following in {"=", "+=", "-=", "++", "--"}:
            return True
    return False


def _script_constructor_expression_end(
    tokens: Sequence[_Token],
    start: int,
    *,
    aliases: Mapping[str, _ConstructorAlias],
) -> int | None:
    offset = start + 1 if start < len(tokens) and tokens[start].value == "new" else start
    if offset >= len(tokens):
        return None
    if tokens[offset].kind == "identifier" and tokens[offset].value in aliases:
        opening = offset + 1
        if (
            aliases[tokens[offset].value].kind == "factory"
            and opening + 2 < len(tokens)
            and tokens[opening].value == "."
            and tokens[opening + 1].value == "Router"
        ):
            opening += 2
        if opening < len(tokens) and tokens[opening].value == "(":
            return _matching_symbol(tokens, opening, "(", ")")
    if (
        offset + 4 < len(tokens)
        and tokens[offset].value == "require"
        and tokens[offset + 1].value == "("
    ):
        first_close = _matching_symbol(tokens, offset + 1, "(", ")")
        if (
            first_close is not None
            and first_close + 1 < len(tokens)
            and tokens[first_close + 1].value == "("
        ):
            return _matching_symbol(tokens, first_close + 1, "(", ")")
    return None


def _script_declaration_ends(tokens: Sequence[_Token], end: int) -> bool:
    if end + 1 == len(tokens) or tokens[end + 1].value == ";":
        return True
    following = tokens[end + 1]
    return following.line > tokens[end].line and following.kind == "identifier"


def _script_receiver_rebound(
    tokens: Sequence[_Token], name: str, *, declaration_index: int
) -> bool:
    for index, token in enumerate(tokens):
        if token.kind != "identifier" or token.value != name or index == declaration_index:
            continue
        previous = tokens[index - 1].value if index else ""
        following = tokens[index + 1].value if index + 1 < len(tokens) else ""
        if previous in {
            "++",
            "--",
            "class",
            "const",
            "function",
            "import",
            "let",
            "var",
        } or following in {
            "++",
            "--",
            "=",
            "+=",
            "-=",
            "in",
            "of",
        }:
            return True
    return False


def _script_brace_depths(tokens: Sequence[_Token]) -> tuple[int, ...]:
    depth = 0
    depths: list[int] = []
    for token in tokens:
        if token.value == "}":
            depth = max(0, depth - 1)
        depths.append(depth)
        if token.value == "{":
            depth += 1
    return tuple(depths)


def _script_scope_paths(tokens: Sequence[_Token]) -> tuple[tuple[int, ...], ...]:
    stack: list[int] = []
    paths: list[tuple[int, ...]] = []
    for index, token in enumerate(tokens):
        if token.value == "}" and stack:
            stack.pop()
        paths.append(tuple(stack))
        if token.value == "{":
            stack.append(index)
    return tuple(paths)


def _script_function_body_ranges(  # noqa: C901
    tokens: Sequence[_Token],
) -> tuple[tuple[int, int], ...]:
    ranges: set[tuple[int, int]] = set()
    for index, token in enumerate(tokens):
        if token.value == "=>" and index + 1 < len(tokens):
            if tokens[index + 1].value == "{":
                closing = _matching_symbol(tokens, index + 1, "{", "}")
                if closing is not None:
                    ranges.add((index + 1, closing))
            else:
                expression_end = _script_arrow_expression_end(tokens, index)
                if expression_end > index + 1:
                    ranges.add((index, expression_end))
        opening: int | None = None
        if token.value == "function":
            opening = next(
                (
                    offset
                    for offset in range(index + 1, min(len(tokens), index + 8))
                    if tokens[offset].value == "("
                ),
                None,
            )
        elif (
            token.kind == "identifier"
            and token.value
            not in {"catch", "for", "if", "switch", "while", "with"}
            and index + 1 < len(tokens)
            and tokens[index + 1].value == "("
        ):
            opening = index + 1
        if opening is not None:
            parameters_end = _matching_symbol(tokens, opening, "(", ")")
            if (
                parameters_end is not None
                and parameters_end + 1 < len(tokens)
                and tokens[parameters_end + 1].value == "{"
            ):
                closing = _matching_symbol(tokens, parameters_end + 1, "{", "}")
                if closing is not None:
                    ranges.add((parameters_end + 1, closing))
    return tuple(sorted(ranges))


def _script_arrow_expression_end(tokens: Sequence[_Token], arrow: int) -> int:
    depths = {"(": 0, "[": 0, "{": 0}
    closing_to_opening = {")": "(", "]": "[", "}": "{"}
    for index in range(arrow + 1, len(tokens)):
        value = tokens[index].value
        if value in depths:
            depths[value] += 1
            continue
        if value in closing_to_opening:
            opening = closing_to_opening[value]
            if depths[opening] == 0:
                return index
            depths[opening] -= 1
            continue
        if value in {",", ";"} and not any(depths.values()):
            return index
    return len(tokens)


def _innermost_function_body(
    function_bodies: Sequence[tuple[int, int]], index: int
) -> tuple[int, int] | None:
    containing = [body for body in function_bodies if body[0] < index < body[1]]
    return max(containing, key=lambda body: body[0], default=None)


def _script_call_argument_ranges(
    tokens: Sequence[_Token], opening: int, closing: int
) -> tuple[tuple[int, int], ...]:
    if opening + 1 >= closing:
        return ()
    arguments: list[tuple[int, int]] = []
    start = opening + 1
    depths = {"(": 0, "[": 0, "{": 0}
    closing_to_opening = {")": "(", "]": "[", "}": "{"}
    for index in range(start, closing):
        value = tokens[index].value
        if value in depths:
            depths[value] += 1
        elif value in closing_to_opening:
            key = closing_to_opening[value]
            depths[key] = max(0, depths[key] - 1)
        elif value == "," and not any(depths.values()):
            if start == index:
                return ()
            arguments.append((start, index))
            start = index + 1
    if start == closing:
        return tuple(arguments)
    arguments.append((start, closing))
    return tuple(arguments)


def _direct_callback_body(
    tokens: Sequence[_Token],
    function_bodies: Sequence[tuple[int, int]],
    argument: tuple[int, int],
) -> tuple[int, int] | None:
    start, end = argument
    if start >= end:
        return None
    body_start: int | None = None
    if tokens[start].value == "function":
        opening = next(
            (index for index in range(start + 1, end) if tokens[index].value == "("),
            None,
        )
        if opening is not None:
            parameters_end = _matching_symbol(tokens, opening, "(", ")")
            if parameters_end is not None and parameters_end + 1 < end:
                body_start = parameters_end + 1
    elif tokens[start].value == "(":
        parameters_end = _matching_symbol(tokens, start, "(", ")")
        if (
            parameters_end is not None
            and parameters_end + 2 < end
            and tokens[parameters_end + 1].value == "=>"
        ):
            body_start = parameters_end + 2
    elif (
        start + 2 < end
        and tokens[start].kind == "identifier"
        and tokens[start + 1].value == "=>"
    ):
        body_start = start + 2
    if body_start is None or tokens[body_start].value != "{":
        return None
    body_end = _matching_symbol(tokens, body_start, "{", "}")
    body = (body_start, body_end) if body_end is not None and body_end + 1 == end else None
    return body if body in function_bodies else None


def _script_server_callbacks(
    tokens: Sequence[_Token], *, function_bodies: Sequence[tuple[int, int]]
) -> tuple[_ServerCallback, ...]:
    aliases = _script_server_aliases(tokens)
    callbacks: list[_ServerCallback] = []
    for index in range(len(tokens) - 4):
        alias = aliases.get(tokens[index].value)
        if (
            alias is None
            or alias.declaration_index >= index
            or tokens[index + 1].value != "."
            or tokens[index + 2].value != "createServer"
            or tokens[index + 3].value != "("
            or _script_receiver_rebound(
                tokens,
                tokens[index].value,
                declaration_index=alias.declaration_index,
            )
            or _script_route_method_mutated(
                tokens,
                tokens[index].value,
                "createServer",
                before=index,
            )
        ):
            continue
        closing = _matching_symbol(tokens, index + 3, "(", ")")
        if closing is None or not _script_declaration_ends(tokens, closing):
            continue
        arguments = _script_call_argument_ranges(tokens, index + 3, closing)
        if len(arguments) not in {1, 2}:
            continue
        listener = arguments[-1]
        body = _direct_callback_body(tokens, function_bodies, listener)
        if body is None:
            continue
        request_name = _script_callback_first_parameter(tokens, body_start=body[0])
        if not request_name:
            continue
        required = alias.required_lines | frozenset(
            {tokens[index].line, tokens[body[0]].line}
        )
        callbacks.append(_ServerCallback(body[0], body[1], request_name, required))
    return tuple(callbacks)


def _script_server_aliases(tokens: Sequence[_Token]) -> dict[str, _ConstructorAlias]:
    packages = {"http", "https", "node:http", "node:https"}
    candidates: dict[str, list[_ConstructorAlias]] = {}
    require_shadowed = _script_require_shadowed(tokens)
    for index in range(len(tokens) - 4):
        name = ""
        package = ""
        declaration_index = -1
        end = -1
        if (
            index + 6 < len(tokens)
            and not require_shadowed
            and tokens[index].value == "const"
            and tokens[index + 1].kind == "identifier"
            and tokens[index + 2].value == "="
            and tokens[index + 3].value == "require"
            and tokens[index + 4].value == "("
            and tokens[index + 5].kind == "string"
            and tokens[index + 6].value == ")"
        ):
            name = tokens[index + 1].value
            package = tokens[index + 5].value
            declaration_index = index + 1
            end = index + 6
        elif (
            tokens[index].value == "import"
            and tokens[index + 1].kind == "identifier"
            and tokens[index + 2].value == "from"
            and tokens[index + 3].kind == "string"
        ):
            name = tokens[index + 1].value
            package = tokens[index + 3].value
            declaration_index = index + 1
            end = index + 3
        elif (
            index + 5 < len(tokens)
            and tokens[index].value == "import"
            and tokens[index + 1].value == "*"
            and tokens[index + 2].value == "as"
            and tokens[index + 3].kind == "identifier"
            and tokens[index + 4].value == "from"
            and tokens[index + 5].kind == "string"
        ):
            name = tokens[index + 3].value
            package = tokens[index + 5].value
            declaration_index = index + 3
            end = index + 5
        if (
            name
            and package in packages
            and _script_declaration_ends(tokens, end)
        ):
            candidates.setdefault(name, []).append(
                _ConstructorAlias(
                    "server",
                    frozenset(token.line for token in tokens[index : end + 1]),
                    declaration_index,
                )
            )
    return {name: items[0] for name, items in candidates.items() if len(items) == 1}


def _script_callback_first_parameter(
    tokens: Sequence[_Token], *, body_start: int
) -> str:
    if body_start < 1:
        return ""
    marker = body_start - 1
    if tokens[marker].value == "=>":
        if marker > 0 and tokens[marker - 1].kind == "identifier":
            return tokens[marker - 1].value
        if marker > 1 and tokens[marker - 1].value == ")":
            opening = _matching_opening_symbol(tokens, marker - 1, "(", ")")
            if opening is not None and opening + 1 < marker:
                candidate = tokens[opening + 1]
                return candidate.value if candidate.kind == "identifier" else ""
    for index in range(max(0, body_start - 12), body_start):
        if tokens[index].value != "function":
            continue
        opening = next(
            (offset for offset in range(index + 1, body_start) if tokens[offset].value == "("),
            None,
        )
        if opening is not None and opening + 1 < body_start:
            candidate = tokens[opening + 1]
            return candidate.value if candidate.kind == "identifier" else ""
    return ""


def _script_registered_routes(  # noqa: PLR0913
    source_file: str,
    tokens: Sequence[_Token],
    bindings: Mapping[str, _Binding],
    receiver_bindings: Mapping[str, _ReceiverBinding],
    queries: tuple[_QueryFact, ...],
    *,
    function_bodies: Sequence[tuple[int, int]],
    scope_paths: Sequence[tuple[int, ...]],
    dead_ranges: Sequence[tuple[int, int]],
) -> list[_RouteFact]:
    facts: list[_RouteFact] = []
    depths = _script_brace_depths(tokens)
    for index in range(len(tokens) - 5):
        receiver = tokens[index]
        dot = tokens[index + 1]
        method_token = tokens[index + 2]
        opening = tokens[index + 3]
        argument = tokens[index + 4]
        comma = tokens[index + 5]
        method = method_token.value.upper()
        receiver_binding = receiver_bindings.get(receiver.value)
        if (
            receiver.kind != "identifier"
            or receiver_binding is None
            or receiver_binding.declaration_index >= index
            or depths[index] != 0
            or not _script_expression_statement_start(tokens, index)
            or _token_in_ranges(index, dead_ranges)
            or dot.value != "."
            or method not in {"GET", "HEAD", "OPTIONS"}
            or opening.value != "("
            or comma.value != ","
            or _script_route_method_mutated(
                tokens,
                receiver.value,
                method_token.value,
                before=index,
            )
        ):
            continue
        closing = _matching_symbol(tokens, index + 3, "(", ")")
        second_argument_end = (
            closing - 1
            if closing is not None and tokens[closing - 1].value == ","
            else closing
        )
        if (
            closing is None
            or second_argument_end is None
            or second_argument_end <= index + 6
            or not _script_expression_statement_end(tokens, closing)
            or (
                index > 0
                and tokens[index - 1].value == "do"
                and _script_do_while_end(tokens, index - 1) is None
            )
        ):
            continue
        required = frozenset(range(receiver.line, comma.line + 1))
        required = required | receiver_binding.required_lines
        path = _safe_route(argument.value) if argument.kind == "string" else ""
        if argument.kind == "identifier":
            binding = _visible_script_binding(
                bindings,
                argument.value,
                use_index=index + 4,
                scope_paths=scope_paths,
            )
        else:
            binding = None
        if binding is not None:
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
                _queries_in_call(
                    tokens,
                    function_bodies,
                    index + 3,
                    closing,
                    queries,
                ),
            )
        )
    return facts


def _queries_in_call(
    tokens: Sequence[_Token],
    function_bodies: Sequence[tuple[int, int]],
    opening: int,
    closing: int,
    queries: tuple[_QueryFact, ...],
) -> tuple[_QueryFact, ...]:
    arguments = _script_call_argument_ranges(tokens, opening, closing)
    callback = (
        _direct_callback_body(tokens, function_bodies, arguments[1])
        if len(arguments) >= _MIN_ROUTE_ARGUMENTS
        else None
    )
    if callback is None:
        arrows = [
            index
            for index in range(opening + 1, closing)
            if tokens[index].value == "=>"
        ]
        if len(arrows) != 1 or any(
            tokens[index].value == "function" for index in range(arrows[0] + 1, closing)
        ):
            return ()
        arrow_body = next(
            (body for body in function_bodies if body[0] == arrows[0]),
            None,
        )
        if arrow_body is None:
            return ()
        request_name = _script_arrow_first_parameter(tokens, arrow=arrows[0])
        if not request_name or _script_identifier_rebound_in_range(
            tokens,
            request_name,
            start=arrow_body[0] + 1,
            end=arrow_body[1],
        ):
            return ()
        return tuple(
            query
            for query in queries
            if arrows[0] < query.token_index < closing
            and query.root == request_name
            and _innermost_function_body(function_bodies, query.token_index) == arrow_body
        )
    request_name = _script_callback_first_parameter(tokens, body_start=callback[0])
    if not request_name or _script_identifier_rebound_in_range(
        tokens,
        request_name,
        start=callback[0] + 1,
        end=callback[1],
    ):
        return ()
    return tuple(
        query
        for query in queries
        if callback[0] < query.token_index < callback[1]
        and query.root == request_name
        and _innermost_function_body(function_bodies, query.token_index) == callback
    )


def _script_arrow_first_parameter(tokens: Sequence[_Token], *, arrow: int) -> str:
    if arrow < 1:
        return ""
    previous = tokens[arrow - 1]
    if previous.kind == "identifier":
        return previous.value
    if previous.value != ")":
        return ""
    opening = _matching_opening_symbol(tokens, arrow - 1, "(", ")")
    if opening is None or opening + 1 >= arrow:
        return ""
    candidate = tokens[opening + 1]
    return candidate.value if candidate.kind == "identifier" else ""


def _script_identifier_rebound_in_range(
    tokens: Sequence[_Token],
    name: str,
    *,
    start: int,
    end: int,
) -> bool:
    for index in range(start, min(end, len(tokens))):
        if tokens[index].kind != "identifier" or tokens[index].value != name:
            continue
        previous = tokens[index - 1].value if index > start else ""
        following = tokens[index + 1].value if index + 1 < end else ""
        if previous in {"class", "const", "function", "let", "var"} or following in {
            "++",
            "--",
            "=",
            "+=",
            "-=",
        }:
            return True
    return False


def _script_expression_statement_start(tokens: Sequence[_Token], index: int) -> bool:
    if index == 0:
        return True
    previous = tokens[index - 1]
    return previous.value in {";", "}", "do"} or (
        previous.line < tokens[index].line and previous.value == ")"
    )


def _script_expression_statement_end(tokens: Sequence[_Token], closing: int) -> bool:
    if closing + 1 == len(tokens) or tokens[closing + 1].value == ";":
        return True
    following = tokens[closing + 1]
    return following.line > tokens[closing].line and following.kind == "identifier"


def _script_route_method_mutated(
    tokens: Sequence[_Token], receiver: str, method: str, *, before: int
) -> bool:
    for index in range(before):
        if (
            index + 5 < before
            and tokens[index].value in {"Object", "Reflect"}
            and tokens[index + 1].value == "."
            and tokens[index + 2].value
            in {
                "assign",
                "defineProperties",
                "defineProperty",
                "deleteProperty",
                "set",
                "setPrototypeOf",
            }
            and tokens[index + 3].value == "("
            and tokens[index + 4].value == receiver
            and tokens[index + 5].value == ","
        ):
            return True
        if (
            index + 3 < before
            and tokens[index].value == receiver
            and tokens[index + 1].value == "."
            and tokens[index + 2].value == method
            and tokens[index + 3].value in {"=", "+=", "-=", "++", "--"}
        ):
            return True
        if (
            index + 4 < before
            and tokens[index].value == receiver
            and tokens[index + 1].value == "["
            and tokens[index + 2].kind == "string"
            and tokens[index + 2].value == method
            and tokens[index + 3].value == "]"
            and tokens[index + 4].value in {"=", "+=", "-=", "++", "--"}
        ):
            return True
        if (
            index + 3 < before
            and tokens[index].value in {"const", "let", "var"}
            and tokens[index + 1].kind == "identifier"
            and tokens[index + 2].value == "="
            and tokens[index + 3].value == receiver
        ):
            return True
    return False


def _script_pathname_routes(  # noqa: C901, PLR0913
    source_file: str,
    tokens: Sequence[_Token],
    bindings: Mapping[str, _Binding],
    queries: tuple[_QueryFact, ...],
    *,
    server_callbacks: Sequence[_ServerCallback],
    function_bodies: Sequence[tuple[int, int]],
    scope_paths: Sequence[tuple[int, ...]],
    dead_ranges: Sequence[tuple[int, int]],
) -> list[_RouteFact]:
    facts: list[_RouteFact] = []
    for index in range(len(tokens) - 4):
        if _token_in_ranges(index, dead_ranges):
            continue
        route_argument: _Token | None = None
        path_receiver = ""
        path_attribute = ""
        use_lines: set[int] = set()
        if (
            tokens[index].kind == "identifier"
            and tokens[index + 1].value == "."
            and _request_path_access(tokens[index].value, tokens[index + 2].value)
            and tokens[index + 3].value in {"==", "==="}
        ):
            path_receiver = tokens[index].value
            path_attribute = tokens[index + 2].value
            route_argument = tokens[index + 4]
            use_lines.update(token.line for token in tokens[index : index + 5])
        elif (
            tokens[index].kind in {"identifier", "string"}
            and tokens[index + 1].value in {"==", "==="}
            and tokens[index + 2].kind == "identifier"
            and tokens[index + 3].value == "."
            and _request_path_access(tokens[index + 2].value, tokens[index + 4].value)
        ):
            path_receiver = tokens[index + 2].value
            path_attribute = tokens[index + 4].value
            route_argument = tokens[index]
            use_lines.update(token.line for token in tokens[index : index + 5])
        if route_argument is None:
            continue
        callback = next(
            (
                item
                for item in server_callbacks
                if item.body_start < index < item.body_end
                and _innermost_function_body(function_bodies, index)
                == (item.body_start, item.body_end)
            ),
            None,
        )
        if callback is None:
            continue
        receiver_lines = _script_native_path_receiver_lines(
            tokens,
            path_receiver,
            path_attribute=path_attribute,
            callback=callback,
            use_index=index,
            scope_paths=scope_paths,
        )
        if not receiver_lines:
            continue
        method_lines = _nearby_get_method_lines(
            tokens,
            index,
            request_name=callback.request_name,
        )
        if not method_lines:
            continue
        required = (
            frozenset(use_lines | method_lines)
            | callback.required_lines
            | receiver_lines
        )
        path = _safe_route(route_argument.value) if route_argument.kind == "string" else ""
        if route_argument.kind == "identifier":
            binding = _visible_script_binding(
                bindings,
                route_argument.value,
                use_index=index,
                scope_paths=scope_paths,
            )
        else:
            binding = None
        if binding is not None:
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
                _queries_in_if_branch(
                    tokens,
                    index,
                    queries,
                    callback=callback,
                    function_bodies=function_bodies,
                ),
            )
        )
    return facts


def _script_native_path_receiver_lines(  # noqa: PLR0913
    tokens: Sequence[_Token],
    receiver: str,
    *,
    path_attribute: str,
    callback: _ServerCallback,
    use_index: int,
    scope_paths: Sequence[tuple[int, ...]],
) -> frozenset[int]:
    if path_attribute != "pathname" or not receiver:
        return frozenset()
    if _script_declaration_counts(tokens).get("URL", 0):
        return frozenset()
    matches: list[tuple[int, int]] = []
    for index in range(callback.body_start + 1, use_index):
        if (
            tokens[index].value != "const"
            or index + 1 >= use_index
            or tokens[index + 1].value != receiver
        ):
            continue
        equals = _script_binding_equals(tokens, index + 2)
        if (
            equals is None
            or equals + 7 >= use_index
            or tokens[equals + 1].value != "new"
            or tokens[equals + 2].value != "URL"
            or tokens[equals + 3].value != "("
            or tokens[equals + 4].value != callback.request_name
            or tokens[equals + 5].value != "."
            or tokens[equals + 6].value != "url"
        ):
            continue
        closing = _matching_symbol(tokens, equals + 3, "(", ")")
        if (
            closing is None
            or closing >= use_index
            or not _script_declaration_ends(tokens, closing)
            or scope_paths[index] != scope_paths[use_index]
            or _identifier_reassigned(tokens, receiver, after=closing)
        ):
            continue
        matches.append((index, closing))
    if len(matches) != 1:
        return frozenset()
    start, end = matches[0]
    lines = frozenset(token.line for token in tokens[start : end + 1])
    return lines if len(lines) <= _MAX_REQUIRED_LINES else frozenset()


def _request_path_access(receiver: str, attribute: str) -> bool:
    lowered = receiver.casefold()
    return (attribute == "pathname" and lowered in _URL_PATH_RECEIVERS) or (
        attribute == "path" and lowered in _QUERY_ROOTS
    )


def _queries_in_if_branch(
    tokens: Sequence[_Token],
    route_index: int,
    queries: tuple[_QueryFact, ...],
    *,
    callback: _ServerCallback,
    function_bodies: Sequence[tuple[int, int]],
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
    if _script_identifier_rebound_in_range(
        tokens,
        callback.request_name,
        start=callback.body_start + 1,
        end=callback.body_end,
    ):
        return ()
    return tuple(
        query
        for query in queries
        if start <= query.token_index <= end
        and query.root == callback.request_name
        and _innermost_function_body(function_bodies, query.token_index)
        == (callback.body_start, callback.body_end)
    )


def _nearby_get_method_lines(
    tokens: Sequence[_Token], route_index: int, *, request_name: str
) -> set[int]:
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
            and direct[0].value == request_name
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


def _script_query_facts(
    tokens: Sequence[_Token], *, dead_ranges: Sequence[tuple[int, int]]
) -> tuple[_QueryFact, ...]:
    facts: set[_QueryFact] = set()
    for index in range(len(tokens) - 4):
        if _token_in_ranges(index, dead_ranges) or _script_expression_is_statically_dead(
            tokens,
            index,
        ):
            continue
        if (
            tokens[index].kind == "identifier"
            and tokens[index].value.casefold() in _QUERY_ROOTS
            and tokens[index + 1].value == "."
            and tokens[index + 2].value in {"query", "queryParams", "query_params"}
        ):
            if tokens[index + 3].value == "." and tokens[index + 4].kind == "identifier":
                name = tokens[index + 4].value
                if name not in {"get", "has"} and _safe_query_name(name):
                    facts.add(
                        _QueryFact(
                            name,
                            tokens[index + 4].line,
                            index + 4,
                            tokens[index].value,
                        )
                    )
            if (
                index + 6 < len(tokens)
                and tokens[index + 3].value == "."
                and tokens[index + 4].value in {"get", "has"}
                and tokens[index + 5].value == "("
                and tokens[index + 6].kind == "string"
                and _safe_query_name(tokens[index + 6].value)
            ):
                facts.add(
                    _QueryFact(
                        tokens[index + 6].value,
                        tokens[index + 6].line,
                        index + 6,
                        tokens[index].value,
                    )
                )
            if (
                index + 5 < len(tokens)
                and tokens[index + 3].value == "["
                and tokens[index + 4].kind == "string"
                and tokens[index + 5].value == "]"
                and _safe_query_name(tokens[index + 4].value)
            ):
                facts.add(
                    _QueryFact(
                        tokens[index + 4].value,
                        tokens[index + 4].line,
                        index + 4,
                        tokens[index].value,
                    )
                )
    return tuple(sorted(facts, key=lambda fact: (fact.line, fact.name)))


def _script_expression_is_statically_dead(
    tokens: Sequence[_Token], index: int
) -> bool:
    return bool(
        index >= _STATIC_SHORT_CIRCUIT_PREFIX_TOKENS
        and tokens[index - 2].kind == "identifier"
        and tokens[index - 2].value == "false"
        and tokens[index - 1].value == "&&"
    )


def _script_static_false_ranges(tokens: Sequence[_Token]) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []
    false_constants = _script_false_constant_names(tokens)
    for index in range(len(tokens) - 4):
        keyword = tokens[index].value
        if keyword not in {"for", "if", "while"} or tokens[index + 1].value != "(":
            continue
        condition_end = _matching_symbol(tokens, index + 1, "(", ")")
        if condition_end is None:
            continue
        condition_start = index + 2
        if keyword == "for":
            separators = _script_top_level_semicolons(
                tokens,
                start=condition_start,
                end=condition_end,
            )
            if len(separators) != _MIN_ROUTE_ARGUMENTS:
                continue
            condition_start = separators[0] + 1
            condition_stop = separators[1]
        else:
            condition_stop = condition_end
        if not _script_is_literal_false(
            tokens,
            condition_start,
            condition_stop,
            false_constants=false_constants,
        ):
            continue
        branch_start = condition_end + 1
        if branch_start >= len(tokens):
            continue
        if tokens[branch_start].value == "{":
            branch_end = _matching_symbol(tokens, branch_start, "{", "}")
        else:
            branch_end = _script_statement_end(tokens, branch_start)
        if branch_end is not None:
            ranges.append((branch_start, branch_end))
    return tuple(ranges)


def _script_false_constant_names(tokens: Sequence[_Token]) -> frozenset[str]:
    depths = _script_brace_depths(tokens)
    names: set[str] = set()
    for index in range(len(tokens) - 3):
        name = tokens[index + 1]
        if (
            depths[index] == 0
            and tokens[index].value == "const"
            and name.kind == "identifier"
            and tokens[index + 2].value == "="
            and tokens[index + 3].value == "false"
            and _script_declaration_ends(tokens, index + 3)
            and not _identifier_reassigned(tokens, name.value, after=index + 3)
        ):
            names.add(name.value)
    return frozenset(names)


def _script_top_level_semicolons(
    tokens: Sequence[_Token], *, start: int, end: int
) -> tuple[int, ...]:
    depths = {"(": 0, "[": 0, "{": 0}
    closing_to_opening = {")": "(", "]": "[", "}": "{"}
    separators: list[int] = []
    for index in range(start, end):
        value = tokens[index].value
        if value in depths:
            depths[value] += 1
        elif value in closing_to_opening:
            depths[closing_to_opening[value]] = max(
                0,
                depths[closing_to_opening[value]] - 1,
            )
        elif value == ";" and not any(depths.values()):
            separators.append(index)
    return tuple(separators)


def _script_is_literal_false(
    tokens: Sequence[_Token],
    start: int,
    end: int,
    *,
    false_constants: frozenset[str],
) -> bool:
    return end == start + 1 and (
        tokens[start].value in {"0", "false"}
        or (
            tokens[start].kind == "identifier"
            and tokens[start].value in false_constants
        )
    )


def _script_statement_end(tokens: Sequence[_Token], start: int) -> int | None:
    depths = {"(": 0, "[": 0, "{": 0}
    closing_to_opening = {")": "(", "]": "[", "}": "{"}
    for index in range(start, len(tokens)):
        value = tokens[index].value
        if value in depths:
            depths[value] += 1
        elif value in closing_to_opening:
            opening = closing_to_opening[value]
            if depths[opening] == 0:
                return index - 1 if index > start else None
            depths[opening] -= 1
        elif value == ";" and not any(depths.values()):
            return index
    return None


def _token_in_ranges(index: int, ranges: Sequence[tuple[int, int]]) -> bool:
    return any(start <= index <= end for start, end in ranges)


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


def _matching_opening_symbol(
    tokens: Sequence[_Token], closing: int, left: str, right: str
) -> int | None:
    depth = 0
    for index in range(closing, -1, -1):
        if tokens[index].value == right:
            depth += 1
        elif tokens[index].value == left:
            depth -= 1
            if depth == 0:
                return index
    return None


def _source_observation_envelope_valid(
    observation: Mapping[str, object], *, snapshot_id: str
) -> bool:
    if (
        not isinstance(observation, Mapping)
        or observation.get("schema") != SOURCE_CONTEXT_OBSERVATION_SCHEMA
        or observation.get("snapshot_id") != snapshot_id
        or observation.get("trust") != SOURCE_CONTEXT_TRUST
        or observation.get("proof_eligible") is not False
    ):
        return False
    provenance = observation.get("provenance")
    return bool(
        isinstance(provenance, Mapping)
        and provenance.get("kind") == SOURCE_CONTEXT_PROVENANCE
        and provenance.get("snapshot_id") == snapshot_id
    )


def _visible_lines(
    observation: Mapping[str, object], *, snapshot_id: str
) -> dict[str, frozenset[int]] | None:
    if not _source_observation_envelope_valid(observation, snapshot_id=snapshot_id):
        return None
    observation_type = observation.get("type")
    if observation_type == "file_list":
        return _zero_line_page(
            observation,
            operation="list_files",
            collection="files",
        )
    if observation_type == "omission_list":
        return _zero_line_page(
            observation,
            operation="list_omissions",
            collection="omissions",
        )
    if observation_type == "excerpt":
        return _excerpt_visible_lines(observation)
    if observation_type == "search_results":
        return _search_visible_lines(observation)
    return None


def _zero_line_page(
    observation: Mapping[str, object],
    *,
    operation: str,
    collection: str,
) -> dict[str, frozenset[int]] | None:
    entries = observation.get(collection)
    if (
        observation.get("operation") != operation
        or not isinstance(entries, list)
        or len(entries) > MAX_SOURCE_CONTEXT_FILE_PAGE
    ):
        return None
    return {}


def _excerpt_visible_lines(
    observation: Mapping[str, object],
) -> dict[str, frozenset[int]] | None:
    path = observation.get("path")
    start = observation.get("start_line")
    end = observation.get("end_line")
    if (
        observation.get("operation") != "excerpt"
        or not isinstance(path, str)
        or type(start) is not int
        or type(end) is not int
        or start < 1
        or end < start
        or end - start + 1 > MAX_SOURCE_CONTEXT_EXCERPT_LINES
    ):
        return None
    return {path: frozenset(range(start, end + 1))}


def _search_visible_lines(
    observation: Mapping[str, object],
) -> dict[str, frozenset[int]] | None:
    matches = observation.get("matches")
    if (
        observation.get("operation") != "search"
        or not isinstance(matches, list)
        or len(matches) > MAX_SOURCE_CONTEXT_SEARCH_MATCHES
    ):
        return None
    visible: dict[str, set[int]] = {}
    for match in matches:
        if not isinstance(match, Mapping) or type(match.get("text_truncated")) is not bool:
            return None
        if match.get("text_truncated") is True:
            continue
        path = match.get("path")
        line = match.get("line")
        if not isinstance(path, str) or type(line) is not int or line < 1:
            return None
        visible.setdefault(path, set()).add(line)
    return {path: frozenset(lines) for path, lines in visible.items()}


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


def _compose_static_route(prefix: str, route: str) -> str:
    if not prefix:
        return route
    if prefix == "/":
        return ""
    return _safe_route(prefix.rstrip("/") + route)


def _safe_query_name(value: object) -> str:
    return (
        value
        if isinstance(value, str)
        and len(value) <= _MAX_QUERY_NAME_CHARS
        and _SAFE_QUERY_NAME_RE.fullmatch(value)
        else ""
    )


__all__ = [
    "SourceNavigationEvidence",
    "SourceNavigationPolicy",
    "build_source_navigation_policy",
]
