"""Ephemeral structural authorization for source-informed HTTP navigation."""

# Local contract errors intentionally use direct, caller-facing messages.
# ruff: noqa: EM101, TRY003

from __future__ import annotations

import ast
import hashlib
import io
import operator
import re
import tokenize
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
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
_MAX_ROUTE_REQUIREMENT_FILES = 8
_MAX_ROUTE_REQUIREMENT_LINES = _MAX_ROUTE_REQUIREMENT_FILES * _MAX_REQUIRED_LINES
_MAX_PYTHON_MOUNT_DEPTH = 8
_MAX_PROMPT_NAVIGATION_ROUTES = 32
_MIN_ROUTE_ARGUMENTS = 2
_VARIADIC_TUPLE_ARGUMENTS = 2
_STATIC_SHORT_CIRCUIT_PREFIX_TOKENS = 2
_ASCII_CONTROL_BOUND = 32
_UNICODE_SURROGATE_START = 0xD800
_UNICODE_SURROGATE_END = 0xDFFF
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
_ROUTE_OMISSION_INFRASTRUCTURE = frozenset(
    {
        ".agents",
        ".aws",
        ".azure",
        ".codex",
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".ssh",
        ".svn",
        ".venv",
        "__pycache__",
        "node_modules",
        "venv",
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
    }
)
_PYTHON_GRAPH_ROOTS = frozenset({("fastapi", "FastAPI"), ("flask", "Flask")})
_PYTHON_GRAPH_COMPONENTS = frozenset({("fastapi", "APIRouter"), ("flask", "Blueprint")})
_PYTHON_ANNOTATION_LEAVES = frozenset(
    {
        ("builtins", "bool"),
        ("builtins", "bytes"),
        ("builtins", "float"),
        ("builtins", "int"),
        ("builtins", "str"),
        ("fastapi", "Request"),
        ("typing", "Any"),
    }
)
_PYTHON_ANNOTATION_GENERIC_ARITY = MappingProxyType(
    {
        ("builtins", "dict"): (2, 2),
        ("builtins", "frozenset"): (1, 1),
        ("builtins", "list"): (1, 1),
        ("builtins", "set"): (1, 1),
        ("builtins", "tuple"): (1, None),
        ("typing", "Mapping"): (2, 2),
        ("typing", "Optional"): (1, 1),
        ("typing", "Sequence"): (1, 1),
        ("typing", "Union"): (2, None),
    }
)
_PYTHON_GRAPH_FROM_IMPORTS = MappingProxyType(
    {
        "fastapi": frozenset({"APIRouter", "FastAPI", "Request"}),
        "flask": frozenset({"Blueprint", "Flask", "request"}),
        "typing": frozenset(
            {
                "Annotated",
                "Any",
                "Callable",
                "ClassVar",
                "Final",
                "Generic",
                "Iterable",
                "Iterator",
                "Literal",
                "Mapping",
                "NamedTuple",
                "Never",
                "NewType",
                "NoReturn",
                "Optional",
                "Protocol",
                "Sequence",
                "TYPE_CHECKING",
                "TypeAlias",
                "TypeVar",
                "Union",
                "cast",
                "overload",
            }
        ),
        "typing_extensions": frozenset(
            {
                "Annotated",
                "Any",
                "Final",
                "Literal",
                "Never",
                "NotRequired",
                "Protocol",
                "Required",
                "Self",
                "TypeAlias",
                "TypeGuard",
                "TypedDict",
                "override",
            }
        ),
    }
)
_PYTHON_FRAMEWORK_MODULE_MEMBERS = MappingProxyType(
    {
        "fastapi": frozenset({"APIRouter", "FastAPI", "Request"}),
        "flask": frozenset({"Blueprint", "Flask", "request"}),
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
    required_lines: frozenset[int] = frozenset()


@dataclass(frozen=True, slots=True, repr=False)
class _PythonQueryBinding:
    framework: str
    required_lines: frozenset[int]


@dataclass(frozen=True, slots=True, repr=False)
class _PythonAnnotationBinding:
    canonical: tuple[str, str]
    required_lines: frozenset[int]


@dataclass(frozen=True, slots=True, repr=False)
class _SourceRequirement:
    source_file: str
    required_lines: frozenset[int]


@dataclass(frozen=True, slots=True, repr=False)
class _RouteFact:
    method: str
    path: str
    source_file: str
    required_lines: frozenset[int]
    query_facts: tuple[_QueryFact, ...] = ()
    supporting_requirements: tuple[_SourceRequirement, ...] = ()
    owner: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, repr=False)
class _RouteOccupancy:
    method: str
    path: str
    owner: tuple[str, ...]
    prefix: bool = False


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
    canonical: tuple[str, str] | None = None
    registration_name: str = ""
    reserves_static_endpoint: bool = False
    reserved_routes: frozenset[tuple[str, str]] = frozenset()
    reserved_path_prefixes: frozenset[tuple[str, str]] = frozenset()
    redirect_slashes: bool = True


@dataclass(frozen=True, slots=True, repr=False)
class _PythonRouteFragment:
    source_file: str
    receiver_name: str
    methods: frozenset[str]
    occupied_methods: frozenset[str]
    path: str
    required_lines: frozenset[int]
    query_facts: tuple[_QueryFact, ...]
    declaration_index: int
    endpoint_name: str
    function_line: int


@dataclass(slots=True, repr=False)
class _PythonModuleAnalysis:
    source_file: str
    tree: ast.Module
    receivers: dict[str, _ReceiverBinding]
    fragments: tuple[_PythonRouteFragment, ...]
    module_stores: dict[str, int]
    mounted_names: frozenset[str]
    shadowed_modules: frozenset[str]
    omitted_paths: frozenset[str]


@dataclass(frozen=True, slots=True, repr=False)
class _PythonSymbolReference:
    receiver_id: tuple[str, str]
    required_lines: frozenset[int]
    declaration_index: int


@dataclass(frozen=True, slots=True, repr=False)
class _PythonMountEdge:
    parent_id: tuple[str, str]
    child_id: tuple[str, str]
    child_name: str
    registration_prefix: str
    overrides_child_prefix: bool
    source_file: str
    required_lines: frozenset[int]
    declaration_index: int
    statement_index: int


@dataclass(slots=True, repr=False)
class _PythonGraphValidation:
    analysis: _PythonModuleAnalysis
    imported: Mapping[str, _PythonSymbolReference]
    mount_indexes: frozenset[int]


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
            fact for fact in self._facts if self._required_atoms(fact).issubset(observed_atoms)
        )

    def _required_atoms(self, fact: _RouteFact) -> frozenset[int]:
        return frozenset(
            self._line_atoms[(requirement.source_file, line)]
            for requirement in _route_requirements(fact)
            for line in requirement.required_lines
        )

    def _query_atoms(self, fact: _RouteFact, query: _QueryFact) -> frozenset[int]:
        return frozenset(
            self._line_atoms[(fact.source_file, line)]
            for line in query.required_lines | {query.line}
        )


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

    @property
    def task_id(self) -> str:
        """Return the active task lineage without exposing observed source text."""
        if self._poisoned or not self._require_task or not self._observation_count:
            return ""
        return self._task_id

    def observe(
        self,
        observation: Mapping[str, object],
        *,
        task_id: str = "",
    ) -> bool:
        """Add only policy-relevant atoms from one trusted snapshot observation."""
        normalized_task_id = str(task_id or "").strip()
        if self._poisoned or (self._require_task and not normalized_task_id):
            self._poison()
            return False
        if self._require_task and self._observation_count and normalized_task_id != self._task_id:
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
                    and self._policy._query_atoms(fact, query).issubset(  # noqa: SLF001
                        self._observed_atoms
                    )
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
        return bool(self._observation_count and self._task_id and action_task_id == self._task_id)

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
    if not _runtime_route_source_coverage_complete(context):
        return SourceNavigationPolicy(context.snapshot_id, (), MappingProxyType({}))
    # Candidate payloads intentionally grant no authority. Every permitted
    # request must be independently recoverable from exact source structure.
    _ = candidate_payloads
    facts: list[_RouteFact] = []
    query_fact_count = 0
    python_sources: list[tuple[str, str]] = []
    try:
        for source in context.files:
            path = PurePosixPath(source.path)
            if _non_runtime_path(path):
                continue
            suffix = path.suffix.casefold()
            if suffix == ".py":
                python_sources.append((source.path, source.text))
                continue
            if suffix in _SCRIPT_SUFFIXES:
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
        python_facts, python_occupancy = _python_repository_route_facts(
            python_sources,
            omitted_paths=frozenset(omission.path for omission in context.omissions),
        )
        facts.extend(python_facts)
        query_fact_count += sum(len(fact.query_facts) for fact in python_facts)
        if len(facts) > _MAX_NAVIGATION_ROUTES or query_fact_count > _MAX_NAVIGATION_QUERY_FACTS:
            raise _PolicyOverflowError  # noqa: TRY301
    except _PolicyOverflowError:
        return SourceNavigationPolicy(context.snapshot_id, (), MappingProxyType({}))
    unambiguous = _globally_unambiguous_route_facts(
        facts,
        occupancy=python_occupancy,
    )
    ordered = tuple(
        sorted(
            unambiguous,
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
            (requirement.source_file, line)
            for fact in ordered
            for requirement in _route_requirements(fact, include_queries=True)
            for line in requirement.required_lines
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


def _globally_unambiguous_route_facts(
    facts: Sequence[_RouteFact],
    *,
    occupancy: Sequence[_RouteOccupancy] = (),
) -> frozenset[_RouteFact]:
    unique = frozenset(facts)
    identities: dict[tuple[str, str], set[_RouteFact]] = {}
    for fact in unique:
        identities.setdefault((fact.method, fact.path), set()).add(fact)
    occupied = (
        *occupancy,
        *(_RouteOccupancy(fact.method, fact.path, fact.owner) for fact in unique if fact.owner),
    )
    return frozenset(
        fact
        for fact in unique
        if len(identities[(fact.method, fact.path)]) == 1
        and (
            not fact.owner
            or {
                item.owner
                for item in occupied
                if item.method == fact.method
                and (
                    fact.path == item.path
                    or (item.prefix and fact.path.startswith(f"{item.path}/"))
                )
            }
            == {fact.owner}
        )
    )


def _requirement_atom(snapshot_id: str, source_file: str, line: int) -> int:
    material = f"{snapshot_id}\0{source_file}\0{line}".encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:16])


def _route_requirements(
    fact: _RouteFact,
    *,
    include_queries: bool = False,
) -> tuple[_SourceRequirement, ...]:
    primary_lines = fact.required_lines
    if include_queries:
        primary_lines |= frozenset(
            line for query in fact.query_facts for line in query.required_lines | {query.line}
        )
    return (
        _SourceRequirement(fact.source_file, primary_lines),
        *fact.supporting_requirements,
    )


def _non_runtime_path(path: PurePosixPath) -> bool:
    lowered_parts = {part.casefold() for part in path.parts[:-1]}
    name = path.name.casefold()
    stem = path.stem.casefold()
    return bool(
        lowered_parts & _NON_RUNTIME_COMPONENTS
        or stem.endswith((".test", ".spec", "_test"))
        or name.startswith("test_")
    )


def _runtime_route_source_coverage_complete(context: RepositoryContext) -> bool:
    for omission in context.omissions:
        path = PurePosixPath(omission.path)
        lowered_parts = {part.casefold() for part in path.parts}
        if _non_runtime_path(path) or lowered_parts & (
            _NON_RUNTIME_COMPONENTS | _ROUTE_OMISSION_INFRASTRUCTURE
        ):
            continue
        if path.suffix.casefold() in _SCRIPT_SUFFIXES | {".py"}:
            return False
        if omission.reason in {
            "excluded_directory",
            "gitignored_directory",
            "unsupported_path",
        }:
            return False
        if omission.reason == "symlink" and not path.suffix:
            return False
    return True


def _python_repository_route_facts(
    sources: Sequence[tuple[str, str]],
    *,
    omitted_paths: frozenset[str],
) -> tuple[list[_RouteFact], tuple[_RouteOccupancy, ...]]:
    shadowed_modules = _python_shadowed_modules(
        sources,
        omitted_paths=omitted_paths,
    )
    analyses_list: list[_PythonModuleAnalysis] = []
    invalid_paths: set[str] = set()
    for source_file, text in sources:
        analysis = _python_module_analysis(
            source_file,
            text,
            shadowed_modules=shadowed_modules,
            omitted_paths=omitted_paths,
        )
        if analysis is None:
            invalid_paths.add(source_file)
        else:
            if not _python_framework_constructor_coverage_complete(
                analysis.tree,
                receivers=analysis.receivers,
            ):
                raise _PolicyOverflowError
            analyses_list.append(analysis)
    analyses = tuple(analyses_list)
    composed, _safe_graph_files, occupancy = _python_composed_route_facts(
        analyses,
        invalid_paths=frozenset(invalid_paths),
    )
    direct = [fact for analysis in analyses for fact in _python_direct_route_facts(analysis)]
    return [*direct, *composed], occupancy


def _python_framework_constructor_coverage_complete(
    tree: ast.Module,
    *,
    receivers: Mapping[str, _ReceiverBinding],
) -> bool:
    if not _python_framework_imports_safe(tree):
        return False

    constructor_aliases, module_aliases = _python_constructor_aliases(tree.body)
    module_stores = _module_scope_stores(tree)
    attribute_mutations = _python_module_attribute_mutations(tree)
    if not _python_framework_module_aliases_safe(tree, module_aliases=module_aliases):
        return False
    if not _python_dynamic_constructor_lookup_safe(
        tree,
        has_constructor_aliases=bool(constructor_aliases),
        has_module_aliases=bool(module_aliases),
    ):
        return False
    accepted_calls = {
        id(value)
        for statement in _definitely_executed_module_statements(tree.body)
        if (assignment := _python_simple_assignment(statement)) is not None
        for name, value in (assignment,)
        if name in receivers and isinstance(value, ast.Call)
    }
    recognized_functions: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        constructor = _python_constructor_call(
            node.func,
            constructor_aliases=constructor_aliases,
            module_aliases=module_aliases,
            module_stores=module_stores,
            attribute_mutations=attribute_mutations,
        )
        if constructor is None or constructor[1] not in _PYTHON_GRAPH_ROOTS:
            continue
        recognized_functions.add(id(node.func))
        if id(node) not in accepted_calls:
            return False

    root_names = {
        name
        for name, (canonical, _lines) in constructor_aliases.items()
        if canonical in _PYTHON_GRAPH_ROOTS
    }
    root_attributes = {
        (name, constructor)
        for name, (module, _lines) in module_aliases.items()
        for candidate_module, constructor in _PYTHON_GRAPH_ROOTS
        if module == candidate_module
    }
    return all(
        not (
            (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id in root_names
                and id(node) not in recognized_functions
            )
            or (
                isinstance(node, ast.Attribute)
                and isinstance(node.ctx, ast.Load)
                and isinstance(node.value, ast.Name)
                and (node.value.id, node.attr) in root_attributes
                and id(node) not in recognized_functions
            )
        )
        for node in ast.walk(tree)
    )


def _python_framework_imports_safe(tree: ast.Module) -> bool:
    dynamic_import_names, importlib_modules = _python_dynamic_import_bindings(tree)
    if any(
        isinstance(node, ast.Call)
        and _python_literal_dynamic_framework_import(
            node,
            import_names=dynamic_import_names,
            module_names=importlib_modules,
        )
        for node in ast.walk(tree)
    ):
        return False
    top_level_imports = {
        id(statement)
        for statement in tree.body
        if isinstance(statement, (ast.Import, ast.ImportFrom))
    }
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        modules = (
            (node.module,)
            if isinstance(node, ast.ImportFrom)
            else tuple(alias.name for alias in node.names)
        )
        framework_import = any(
            module and module.split(".", maxsplit=1)[0] in {"fastapi", "flask"}
            for module in modules
        )
        if framework_import and (
            id(node) not in top_level_imports
            or (
                isinstance(node, ast.ImportFrom)
                and (
                    node.level != 0
                    or node.module not in {"fastapi", "flask"}
                    or any(alias.name == "*" for alias in node.names)
                    or any(
                        alias.name not in _PYTHON_FRAMEWORK_MODULE_MEMBERS[node.module]
                        for alias in node.names
                    )
                )
            )
            or (
                isinstance(node, ast.Import)
                and any(alias.name not in {"fastapi", "flask"} for alias in node.names)
            )
        ):
            return False
    return True


def _python_framework_module_aliases_safe(
    tree: ast.Module,
    *,
    module_aliases: Mapping[str, tuple[str, frozenset[int]]],
) -> bool:
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in module_aliases
        ):
            continue
        parent = parents.get(id(node))
        module = module_aliases[node.id][0]
        if not (
            isinstance(parent, ast.Attribute)
            and parent.value is node
            and parent.attr in _PYTHON_FRAMEWORK_MODULE_MEMBERS[module]
        ):
            return False
    return True


def _python_dynamic_constructor_lookup_safe(
    tree: ast.Module,
    *,
    has_constructor_aliases: bool,
    has_module_aliases: bool,
) -> bool:
    if not (has_constructor_aliases or has_module_aliases):
        return True
    dynamic_names = {"__import__", "eval", "exec", "globals", "locals", "vars"}
    return all(
        not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in dynamic_names
        )
        for node in ast.walk(tree)
    )


def _python_dynamic_import_bindings(
    tree: ast.Module,
) -> tuple[frozenset[str], frozenset[str]]:
    import_names = {"__import__", "import_module"}
    module_names = {"importlib"}
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            module_names.update(
                alias.asname or alias.name
                for alias in statement.names
                if alias.name == "importlib"
            )
        elif isinstance(statement, ast.ImportFrom) and statement.module == "importlib":
            import_names.update(
                alias.asname or alias.name
                for alias in statement.names
                if alias.name == "import_module"
            )
        assignment = _python_simple_assignment(statement)
        if assignment is None:
            continue
        name, value = assignment
        if (isinstance(value, ast.Name) and value.id in import_names) or (
            isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            and value.value.id in module_names
            and value.attr == "import_module"
        ):
            import_names.add(name)
    return frozenset(import_names), frozenset(module_names)


def _python_literal_dynamic_framework_import(
    call: ast.Call,
    *,
    import_names: frozenset[str],
    module_names: frozenset[str],
) -> bool:
    return any(
        module.split(".", maxsplit=1)[0] in {"fastapi", "flask"}
        for module in _python_literal_dynamic_import_names(
            call,
            import_names=import_names,
            module_names=module_names,
        )
    )


def _python_literal_dynamic_import_names(
    call: ast.Call,
    *,
    import_names: frozenset[str],
    module_names: frozenset[str],
) -> frozenset[str]:
    function = call.func
    dynamic_import = bool(
        (isinstance(function, ast.Name) and function.id in import_names)
        or (
            isinstance(function, ast.Attribute)
            and isinstance(function.value, ast.Name)
            and function.value.id in module_names
            and function.attr == "import_module"
        )
    )
    if not dynamic_import:
        return frozenset()
    candidates = [*call.args[:1]]
    candidates.extend(
        keyword.value for keyword in call.keywords if keyword.arg in {"name", "package"}
    )
    return frozenset(
        module
        for candidate in candidates
        if (module := _python_static_import_name(candidate)) is not None
    )


def _python_static_import_name(value: ast.expr) -> str | None:
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
        left = _python_static_import_name(value.left)
        right = _python_static_import_name(value.right)
        if left is not None and right is not None and len(left) + len(right) <= _MAX_ROUTE_CHARS:
            return left + right
    return None


def _python_shadowed_modules(
    sources: Sequence[tuple[str, str]],
    *,
    omitted_paths: frozenset[str],
) -> frozenset[str]:
    shadowed: set[str] = set()
    import_modules = {
        *(module for module, _constructor in _PYTHON_FRAMEWORK_CONSTRUCTORS),
        "typing",
        "typing_extensions",
    }
    source_paths = (source_file for source_file, _text in sources)
    for raw_path in (*source_paths, *omitted_paths):
        path = PurePosixPath(raw_path)
        for module in import_modules:
            if (
                path.name == module
                or path.name.startswith(f"{module}.")
                or (path.name == "__init__.py" and path.parent.name == module)
            ):
                shadowed.add(module)
    return frozenset(shadowed)


def _python_module_analysis(
    source_file: str,
    text: str,
    *,
    shadowed_modules: frozenset[str],
    omitted_paths: frozenset[str],
) -> _PythonModuleAnalysis | None:
    try:
        token_count = sum(1 for _token in tokenize.generate_tokens(io.StringIO(text).readline))
        if token_count > _MAX_TOKENS_PER_FILE:
            raise _PolicyOverflowError  # noqa: TRY301
        compile(
            text,
            source_file,
            "exec",
            dont_inherit=True,
        )  # Compile only; repository code is never executed.
        tree = ast.parse(text)
    except _PolicyOverflowError:
        raise
    except (
        IndentationError,
        MemoryError,
        RecursionError,
        SyntaxError,
        tokenize.TokenError,
        ValueError,
    ):
        return None
    receiver_bindings = {
        name: binding
        for name, binding in _python_receiver_bindings(
            tree,
            suppress_mounted=False,
        ).items()
        if not binding.canonical or binding.canonical[0] not in shadowed_modules
    }
    if not receiver_bindings:
        return _PythonModuleAnalysis(
            source_file,
            tree,
            {},
            (),
            _module_scope_stores(tree),
            _python_mounted_receiver_names(tree),
            shadowed_modules,
            omitted_paths,
        )
    fragments: list[_PythonRouteFragment] = []
    module_stores = _module_scope_stores(tree)
    query_bindings = _python_query_bindings(tree, module_stores=module_stores)
    for node in _definitely_executed_module_functions(tree.body):
        query_facts = _python_query_facts(
            node,
            query_roots=frozenset(query_bindings),
        )
        for decorator in node.decorator_list:
            fragment = _python_decorator_fragment(
                decorator,
                function=node,
                receiver_bindings=receiver_bindings,
            )
            if fragment is None:
                continue
            receiver_name, methods, occupied_methods, path, lines = fragment
            receiver = receiver_bindings[receiver_name]
            annotation_requirements = _python_function_annotation_requirements(
                node,
                tree=tree,
                module_stores=module_stores,
                framework=(receiver.canonical or ("", ""))[0],
            )
            if annotation_requirements is None:
                continue
            lines |= annotation_requirements
            queries = tuple(
                _QueryFact(
                    name=fact.name,
                    line=fact.line,
                    root=fact.root,
                    required_lines=query_bindings[fact.root].required_lines,
                )
                for fact in query_facts
                if query_bindings[fact.root].framework == (receiver.canonical or ("", ""))[0]
            )
            fragments.append(
                _PythonRouteFragment(
                    source_file=source_file,
                    receiver_name=receiver_name,
                    methods=methods,
                    occupied_methods=occupied_methods,
                    path=path,
                    required_lines=lines,
                    query_facts=queries,
                    declaration_index=min(_node_lines(decorator)),
                    endpoint_name=node.name,
                    function_line=node.lineno,
                )
            )
    return _PythonModuleAnalysis(
        source_file=source_file,
        tree=tree,
        receivers=receiver_bindings,
        fragments=tuple(fragments),
        module_stores=module_stores,
        mounted_names=_python_mounted_receiver_names(tree),
        shadowed_modules=shadowed_modules,
        omitted_paths=omitted_paths,
    )


def _python_direct_route_facts(
    analysis: _PythonModuleAnalysis,
) -> list[_RouteFact]:
    facts: list[_RouteFact] = []
    for fragment in analysis.fragments:
        binding = analysis.receivers.get(fragment.receiver_name)
        if (
            binding is None
            or _python_graph_root(binding)
            or _python_graph_component(binding)
            or fragment.receiver_name in analysis.mounted_names
        ):
            continue
        path = _compose_static_route(binding.path_prefix, fragment.path)
        if not path:
            continue
        facts.extend(
            _RouteFact(
                method=method,
                path=path,
                source_file=fragment.source_file,
                required_lines=fragment.required_lines,
                query_facts=fragment.query_facts,
                owner=("python-direct", fragment.source_file, fragment.receiver_name),
            )
            for method in fragment.methods
        )
    return facts


def _python_graph_component(binding: _ReceiverBinding) -> bool:
    return binding.canonical in _PYTHON_GRAPH_COMPONENTS


def _python_graph_root(binding: _ReceiverBinding) -> bool:
    return binding.canonical in _PYTHON_GRAPH_ROOTS


def _python_composed_route_facts(  # noqa: C901 - bounded graph validation.
    analyses: Sequence[_PythonModuleAnalysis],
    *,
    invalid_paths: frozenset[str],
) -> tuple[list[_RouteFact], frozenset[str], tuple[_RouteOccupancy, ...]]:
    analysis_by_file = {analysis.source_file: analysis for analysis in analyses}
    receivers = {
        (analysis.source_file, name): binding
        for analysis in analyses
        for name, binding in analysis.receivers.items()
    }
    candidate_edges, safe_files, unresolved_mount = _python_safe_mount_edges(
        analyses,
        analysis_by_file=analysis_by_file,
        receivers=receivers,
        invalid_paths=invalid_paths,
    )
    root_files = {
        source_file
        for (source_file, _name), binding in receivers.items()
        if _python_graph_root(binding)
    }
    if unresolved_mount or not root_files.issubset(safe_files):
        raise _PolicyOverflowError
    fragments: dict[tuple[str, str], list[_PythonRouteFragment]] = {}
    for analysis in analyses:
        for fragment in analysis.fragments:
            fragments.setdefault(
                (fragment.source_file, fragment.receiver_name),
                [],
            ).append(fragment)
    rooted_occupancy, occupancy_complete = _python_candidate_root_occupancy(
        receivers=receivers,
        edges=candidate_edges,
        fragments=fragments,
    )
    if not occupancy_complete:
        raise _PolicyOverflowError
    receivers = {
        receiver_id: binding
        for receiver_id, binding in receivers.items()
        if receiver_id[0] in safe_files
    }
    edges = tuple(
        edge
        for edge in candidate_edges
        if edge.source_file in safe_files and edge.child_id[0] in safe_files
    )
    incoming_counts: dict[tuple[str, str], int] = {}
    for edge in edges:
        incoming_counts[edge.child_id] = incoming_counts.get(edge.child_id, 0) + 1
    outgoing: dict[tuple[str, str], list[_PythonMountEdge]] = {}
    for edge in edges:
        if incoming_counts.get(edge.child_id) != 1:
            continue
        outgoing.setdefault(edge.parent_id, []).append(edge)

    rooted_facts: list[tuple[tuple[str, str], _RouteFact]] = []
    for receiver_id, binding in sorted(receivers.items()):
        if not _python_graph_root(binding):
            continue
        initial_requirements = _merge_python_requirements(
            {},
            receiver_id[0],
            binding.required_lines,
        )
        if initial_requirements is None:
            continue
        root_facts: list[_RouteFact] = []
        _walk_python_mount_graph(
            receiver_id=receiver_id,
            route_prefix=binding.path_prefix,
            requirements=initial_requirements,
            cutoff=None,
            depth=0,
            visited=frozenset(),
            receivers=receivers,
            outgoing=outgoing,
            fragments=fragments,
            facts=root_facts,
        )
        rooted_facts.extend(
            (receiver_id, fact)
            for fact in _python_unambiguous_root_facts(
                root_facts,
                root=binding,
            )
        )
        if len(rooted_facts) > _MAX_NAVIGATION_ROUTES:
            raise _PolicyOverflowError
    return (
        _python_single_root_facts(
            rooted_facts,
            rooted_occupancy=rooted_occupancy,
        ),
        frozenset(safe_files),
        tuple(rooted_occupancy),
    )


def _python_candidate_root_occupancy(
    *,
    receivers: Mapping[tuple[str, str], _ReceiverBinding],
    edges: Sequence[_PythonMountEdge],
    fragments: Mapping[tuple[str, str], Sequence[_PythonRouteFragment]],
) -> tuple[list[_RouteOccupancy], bool]:
    outgoing: dict[tuple[str, str], list[_PythonMountEdge]] = {}
    for edge in edges:
        outgoing.setdefault(edge.parent_id, []).append(edge)
    occupancy: list[_RouteOccupancy] = []
    for receiver_id, binding in sorted(receivers.items()):
        if not _python_graph_root(binding):
            continue
        owner = _python_route_owner(receiver_id)
        builtin_owner = _python_builtin_route_owner(receiver_id)
        occupancy.extend(
            _RouteOccupancy(method, path, builtin_owner) for method, path in binding.reserved_routes
        )
        for path in {path for _method, path in binding.reserved_routes}:
            alternate = _python_redirect_request_path(binding, path)
            if alternate:
                occupancy.extend(
                    _RouteOccupancy(method, alternate, owner)
                    for method in ("GET", "HEAD", "OPTIONS")
                )
        occupancy.extend(
            _RouteOccupancy(method, path, builtin_owner, prefix=True)
            for method, path in binding.reserved_path_prefixes
        )
        if len(occupancy) > _MAX_NAVIGATION_ROUTES:
            return occupancy, False
        if not _walk_python_candidate_paths(
            owner=owner,
            root=binding,
            receiver_id=receiver_id,
            route_prefix=binding.path_prefix,
            depth=0,
            visited=frozenset(),
            receivers=receivers,
            outgoing=outgoing,
            fragments=fragments,
            occupancy=occupancy,
        ):
            return occupancy, False
    return occupancy, True


def _walk_python_candidate_paths(  # noqa: C901, PLR0913 - bounded graph traversal.
    *,
    owner: tuple[str, ...],
    root: _ReceiverBinding,
    receiver_id: tuple[str, str],
    route_prefix: str,
    depth: int,
    visited: frozenset[tuple[str, str]],
    receivers: Mapping[tuple[str, str], _ReceiverBinding],
    outgoing: Mapping[tuple[str, str], Sequence[_PythonMountEdge]],
    fragments: Mapping[tuple[str, str], Sequence[_PythonRouteFragment]],
    occupancy: list[_RouteOccupancy],
) -> bool:
    if depth > _MAX_PYTHON_MOUNT_DEPTH:
        return False
    if receiver_id in visited:
        return True
    binding = receivers.get(receiver_id)
    if binding is None:
        return True
    branch_visited = visited | {receiver_id}
    for fragment in fragments.get(receiver_id, ()):
        path = _compose_static_route(route_prefix, fragment.path)
        if path:
            occupancy.extend(
                _RouteOccupancy(method, path, owner) for method in fragment.occupied_methods
            )
            alternate = _python_redirect_request_path(
                root,
                path,
            )
            if alternate:
                redirect_methods = (
                    frozenset({"GET", "HEAD", "OPTIONS"})
                    if root.canonical == ("fastapi", "FastAPI")
                    else fragment.occupied_methods
                )
                occupancy.extend(
                    _RouteOccupancy(method, alternate, owner) for method in redirect_methods
                )
            if len(occupancy) > _MAX_NAVIGATION_ROUTES:
                return False
    for edge in outgoing.get(receiver_id, ()):
        child_binding = receivers.get(edge.child_id)
        if child_binding is None:
            continue
        child_segment = (
            edge.registration_prefix
            if edge.overrides_child_prefix
            else _join_python_prefixes(
                edge.registration_prefix,
                child_binding.path_prefix,
            )
        )
        if child_segment is None:
            continue
        child_prefix = _join_python_prefixes(route_prefix, child_segment)
        if child_prefix is None:
            continue
        if not _walk_python_candidate_paths(
            owner=owner,
            root=root,
            receiver_id=edge.child_id,
            route_prefix=child_prefix,
            depth=depth + 1,
            visited=branch_visited,
            receivers=receivers,
            outgoing=outgoing,
            fragments=fragments,
            occupancy=occupancy,
        ):
            return False
    return True


def _python_single_root_facts(
    rooted_facts: Sequence[tuple[tuple[str, str], _RouteFact]],
    *,
    rooted_occupancy: Sequence[_RouteOccupancy],
) -> list[_RouteFact]:
    owners: dict[tuple[str, str], set[tuple[str, ...]]] = {}
    for item in rooted_occupancy:
        if item.prefix:
            continue
        owners.setdefault((item.method, item.path), set()).add(item.owner)
    return [
        replace(fact, owner=_python_route_owner(receiver_id))
        for receiver_id, fact in rooted_facts
        if owners.get((fact.method, fact.path), set()) == {_python_route_owner(receiver_id)}
        and not any(
            item.prefix
            and item.method == fact.method
            and (fact.path == item.path or fact.path.startswith(f"{item.path}/"))
            for item in rooted_occupancy
        )
    ]


def _python_route_owner(receiver_id: tuple[str, str]) -> tuple[str, ...]:
    return ("python", *receiver_id)


def _python_builtin_route_owner(receiver_id: tuple[str, str]) -> tuple[str, ...]:
    return ("python-builtin", *receiver_id)


def _python_redirect_request_path(root: _ReceiverBinding, path: str) -> str:
    if path == "/":
        return ""
    if root.canonical == ("fastapi", "FastAPI"):
        if not root.redirect_slashes:
            return ""
        return path[:-1] if path.endswith("/") else f"{path}/"
    if root.canonical == ("flask", "Flask") and path.endswith("/"):
        return path[:-1]
    return ""


def _python_unambiguous_root_facts(
    facts: Sequence[_RouteFact],
    *,
    root: _ReceiverBinding,
) -> tuple[_RouteFact, ...]:
    candidates = tuple(
        {fact for fact in facts if (fact.method, fact.path) not in root.reserved_routes}
    )
    flask_root = root.canonical == ("flask", "Flask")
    identities: dict[object, set[tuple[object, ...]]] = {}
    for fact in candidates:
        collision_key: object = fact.path if flask_root else (fact.method, fact.path)
        identities.setdefault(collision_key, set()).add(
            (
                fact.source_file,
                fact.required_lines,
                fact.supporting_requirements,
            )
        )
    return tuple(
        fact
        for fact in candidates
        if len(identities[fact.path if flask_root else (fact.method, fact.path)]) == 1
    )


def _python_safe_mount_edges(
    analyses: Sequence[_PythonModuleAnalysis],
    *,
    analysis_by_file: Mapping[str, _PythonModuleAnalysis],
    receivers: Mapping[tuple[str, str], _ReceiverBinding],
    invalid_paths: frozenset[str],
) -> tuple[tuple[_PythonMountEdge, ...], set[str], bool]:
    imports_by_file = {
        analysis.source_file: _python_direct_receiver_imports(
            analysis,
            analysis_by_file=analysis_by_file,
            invalid_paths=invalid_paths,
        )
        for analysis in analyses
    }
    candidate_edges = tuple(
        edge
        for analysis in analyses
        for edge in _python_mount_edges(
            analysis,
            receivers=receivers,
            imported=imports_by_file[analysis.source_file],
        )
    )
    consumed_imports = frozenset(
        (edge.source_file, edge.child_name)
        for edge in candidate_edges
        if edge.child_id[0] != edge.source_file
    )
    unsafe_receiver_import = any(
        (source_file, local_name) not in consumed_imports
        for source_file, imported in imports_by_file.items()
        for local_name in imported
    ) or any(
        _python_unaccounted_graph_receiver_imported(
            analysis,
            analysis_by_file=analysis_by_file,
            invalid_paths=invalid_paths,
        )
        for analysis in analyses
    )
    recognized_mounts = frozenset(
        (edge.source_file, edge.statement_index) for edge in candidate_edges
    )
    unresolved_mount = any(
        _python_potential_graph_mount(
            analysis,
            statement,
            imported=imports_by_file[analysis.source_file],
        )
        and (analysis.source_file, statement_index) not in recognized_mounts
        for analysis in analyses
        for statement_index, statement in enumerate(analysis.tree.body)
    )
    registration_collision_files = _python_flask_registration_collision_files(
        candidate_edges,
        receivers=receivers,
    )
    invalid_mount_files = registration_collision_files | _python_mount_cycle_files(candidate_edges)
    edges_by_file: dict[str, list[_PythonMountEdge]] = {}
    for edge in candidate_edges:
        edges_by_file.setdefault(edge.source_file, []).append(edge)
    candidate_safe_files = {
        analysis.source_file
        for analysis in analyses
        if analysis.source_file not in invalid_mount_files
        and _python_graph_module_safe(
            analysis,
            imported=imports_by_file[analysis.source_file],
            mount_edges=edges_by_file.get(analysis.source_file, ()),
        )
        and _python_package_initializers_safe(
            analysis.source_file,
            analysis_by_file=analysis_by_file,
            invalid_paths=invalid_paths,
        )
    }
    dependencies = {
        source_file: frozenset(reference.receiver_id[0] for reference in imported.values())
        for source_file, imported in imports_by_file.items()
    }
    dependency_results: dict[str, bool] = {}
    safe_files = {
        source_file
        for source_file in candidate_safe_files
        if _python_import_dependencies_safe(
            source_file,
            candidate_safe_files=candidate_safe_files,
            dependencies=dependencies,
            visiting=frozenset(),
            results=dependency_results,
        )
    }
    return candidate_edges, safe_files, unresolved_mount or unsafe_receiver_import


def _python_potential_graph_mount(
    analysis: _PythonModuleAnalysis,
    statement: ast.stmt,
    *,
    imported: Mapping[str, _PythonSymbolReference],
) -> bool:
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return False
    function = statement.value.func
    if not (
        isinstance(function, ast.Attribute)
        and isinstance(function.value, ast.Name)
        and function.attr in {"include_router", "register_blueprint"}
    ):
        return False
    local = analysis.receivers.get(function.value.id)
    return bool(
        function.value.id in imported
        or (local is not None and (_python_graph_root(local) or _python_graph_component(local)))
    )


def _python_flask_registration_collision_files(
    edges: Sequence[_PythonMountEdge],
    *,
    receivers: Mapping[tuple[str, str], _ReceiverBinding],
) -> frozenset[str]:
    seen: set[tuple[tuple[str, str], str]] = set()
    unsafe: set[str] = set()
    for edge in edges:
        parent = receivers.get(edge.parent_id)
        child = receivers.get(edge.child_id)
        if (
            parent is None
            or child is None
            or parent.canonical not in {("flask", "Flask"), ("flask", "Blueprint")}
            or child.canonical != ("flask", "Blueprint")
        ):
            continue
        registration = (edge.parent_id, child.registration_name)
        if not child.registration_name or registration in seen:
            unsafe.add(edge.source_file)
        seen.add(registration)
    return frozenset(unsafe)


def _python_mount_cycle_files(
    edges: Sequence[_PythonMountEdge],
) -> frozenset[str]:
    nodes = {receiver_id for edge in edges for receiver_id in (edge.parent_id, edge.child_id)}
    incoming = dict.fromkeys(nodes, 0)
    outgoing: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for edge in edges:
        incoming[edge.child_id] += 1
        outgoing.setdefault(edge.parent_id, []).append(edge.child_id)
    ready = [node for node, count in incoming.items() if count == 0]
    removed: set[tuple[str, str]] = set()
    while ready:
        node = ready.pop()
        if node in removed:
            continue
        removed.add(node)
        for child in outgoing.get(node, ()):
            incoming[child] -= 1
            if incoming[child] == 0:
                ready.append(child)
    return frozenset(node[0] for node in nodes - removed)


def _python_import_dependencies_safe(
    source_file: str,
    *,
    candidate_safe_files: set[str],
    dependencies: Mapping[str, frozenset[str]],
    visiting: frozenset[str],
    results: dict[str, bool],
) -> bool:
    if source_file in results:
        return results[source_file]
    if source_file not in candidate_safe_files or source_file in visiting:
        return False
    branch = visiting | {source_file}
    result = all(
        _python_import_dependencies_safe(
            dependency,
            candidate_safe_files=candidate_safe_files,
            dependencies=dependencies,
            visiting=branch,
            results=results,
        )
        for dependency in dependencies.get(source_file, ())
    )
    results[source_file] = result
    return result


def _python_direct_receiver_imports(
    analysis: _PythonModuleAnalysis,
    *,
    analysis_by_file: Mapping[str, _PythonModuleAnalysis],
    invalid_paths: frozenset[str],
) -> dict[str, _PythonSymbolReference]:
    candidates: dict[str, list[_PythonSymbolReference]] = {}
    for statement in analysis.tree.body:
        if not isinstance(statement, ast.ImportFrom) or statement.level < 1 or not statement.module:
            continue
        target = _python_relative_import_analysis(
            analysis.source_file,
            statement,
            analysis_by_file=analysis_by_file,
            invalid_paths=invalid_paths,
        )
        if target is None:
            continue
        lines = _node_lines(statement)
        if not lines:
            continue
        for alias in statement.names:
            if alias.name == "*":
                continue
            local_name = alias.asname or alias.name
            target_binding = target.receivers.get(alias.name)
            if (
                target_binding is None
                or not _python_graph_component(target_binding)
                or analysis.module_stores.get(local_name) != 1
            ):
                continue
            candidates.setdefault(local_name, []).append(
                _PythonSymbolReference(
                    receiver_id=(target.source_file, alias.name),
                    required_lines=lines,
                    declaration_index=max(lines),
                )
            )
    return {name: references[0] for name, references in candidates.items() if len(references) == 1}


def _python_unaccounted_graph_receiver_imported(
    analysis: _PythonModuleAnalysis,
    *,
    analysis_by_file: Mapping[str, _PythonModuleAnalysis],
    invalid_paths: frozenset[str],
) -> bool:
    dynamic_import_names, importlib_modules = _python_dynamic_import_bindings(analysis.tree)
    if any(
        _python_analysis_defines_graph_receiver(target)
        for node in ast.walk(analysis.tree)
        if isinstance(node, ast.Call)
        for module in _python_literal_dynamic_import_names(
            node,
            import_names=dynamic_import_names,
            module_names=importlib_modules,
        )
        for target in _python_import_module_analyses(
            analysis.source_file,
            module=module,
            level=0,
            analysis_by_file=analysis_by_file,
        )
    ):
        return True
    return any(
        _python_import_statement_uses_graph_receiver(
            analysis.source_file,
            statement,
            analysis_by_file=analysis_by_file,
            invalid_paths=invalid_paths,
        )
        for statement in analysis.tree.body
    )


def _python_import_statement_uses_graph_receiver(
    source_file: str,
    statement: ast.stmt,
    *,
    analysis_by_file: Mapping[str, _PythonModuleAnalysis],
    invalid_paths: frozenset[str],
) -> bool:
    if isinstance(statement, ast.Import):
        return any(
            _python_analysis_defines_graph_receiver(target)
            for alias in statement.names
            for target in _python_import_module_analyses(
                source_file,
                module=alias.name,
                level=0,
                analysis_by_file=analysis_by_file,
            )
        )
    if not isinstance(statement, ast.ImportFrom):
        return False
    return _python_from_import_uses_graph_receiver(
        source_file,
        statement,
        analysis_by_file=analysis_by_file,
        invalid_paths=invalid_paths,
    )


def _python_from_import_uses_graph_receiver(
    source_file: str,
    statement: ast.ImportFrom,
    *,
    analysis_by_file: Mapping[str, _PythonModuleAnalysis],
    invalid_paths: frozenset[str],
) -> bool:
    direct_targets: tuple[_PythonModuleAnalysis, ...] = ()
    if statement.module:
        if statement.level:
            target = _python_relative_import_analysis(
                source_file,
                statement,
                analysis_by_file=analysis_by_file,
                invalid_paths=invalid_paths,
            )
            direct_targets = () if target is None else (target,)
        else:
            direct_targets = _python_import_module_analyses(
                source_file,
                module=statement.module,
                level=0,
                analysis_by_file=analysis_by_file,
            )
    if any(
        (
            alias.name == "*" and _python_analysis_defines_graph_receiver(target)
        )
        or (
            (binding := target.receivers.get(alias.name)) is not None
            and (_python_graph_root(binding) or statement.level == 0)
        )
        for target in direct_targets
        for alias in statement.names
    ):
        return True
    return any(
        _python_analysis_defines_graph_receiver(target)
        for alias in statement.names
        if alias.name != "*"
        for target in _python_import_module_analyses(
            source_file,
            module=(f"{statement.module}.{alias.name}" if statement.module else alias.name),
            level=statement.level,
            analysis_by_file=analysis_by_file,
        )
    )


def _python_import_module_analyses(
    source_file: str,
    *,
    module: str,
    level: int,
    analysis_by_file: Mapping[str, _PythonModuleAnalysis],
) -> tuple[_PythonModuleAnalysis, ...]:
    module_parts = module.split(".")
    if not module_parts or any(not part for part in module_parts):
        return ()
    if level:
        parent_parts = list(PurePosixPath(source_file).parent.parts)
        climb = level - 1
        if not parent_parts or climb >= len(parent_parts):
            return ()
        target = PurePosixPath(*parent_parts[: len(parent_parts) - climb], *module_parts)
        candidates = {f"{target}.py", str(target / "__init__.py")}
        return tuple(
            analysis_by_file[path]
            for path in sorted(candidates)
            if path in analysis_by_file
        )
    target = PurePosixPath(*module_parts)
    suffixes = (f"{target}.py", str(target / "__init__.py"))
    return tuple(
        analysis
        for path, analysis in sorted(analysis_by_file.items())
        if any(path == suffix or path.endswith(f"/{suffix}") for suffix in suffixes)
    )


def _python_analysis_defines_graph_receiver(analysis: _PythonModuleAnalysis) -> bool:
    return any(
        _python_graph_root(binding) or _python_graph_component(binding)
        for binding in analysis.receivers.values()
    )


def _python_relative_import_analysis(
    source_file: str,
    statement: ast.ImportFrom,
    *,
    analysis_by_file: Mapping[str, _PythonModuleAnalysis],
    invalid_paths: frozenset[str],
) -> _PythonModuleAnalysis | None:
    parent_parts = list(PurePosixPath(source_file).parent.parts)
    climb = statement.level - 1
    if not parent_parts or climb >= len(parent_parts):
        return None
    base_parts = parent_parts[: len(parent_parts) - climb]
    module_parts = statement.module.split(".") if statement.module else []
    if not module_parts or any(not part for part in module_parts):
        return None
    target = PurePosixPath(*base_parts, *module_parts)
    source_analysis = analysis_by_file.get(source_file)
    omitted_paths = source_analysis.omitted_paths if source_analysis is not None else frozenset()
    if _python_import_target_omitted(
        target,
        omitted_paths=omitted_paths | invalid_paths,
    ):
        return None
    candidates = {
        path for path in (f"{target}.py", str(target / "__init__.py")) if path in analysis_by_file
    }
    if len(candidates) != 1:
        return None
    return analysis_by_file[next(iter(candidates))]


def _python_import_target_omitted(
    target: PurePosixPath,
    *,
    omitted_paths: frozenset[str],
) -> bool:
    for raw_path in omitted_paths:
        omitted = PurePosixPath(raw_path)
        if omitted == target or target in omitted.parents:
            return True
        if omitted.parent == target.parent and (
            omitted.name == target.name or omitted.name.startswith(f"{target.name}.")
        ):
            return True
    return False


def _python_graph_module_safe(
    analysis: _PythonModuleAnalysis,
    *,
    imported: Mapping[str, _PythonSymbolReference],
    mount_edges: Sequence[_PythonMountEdge],
) -> bool:
    if not _python_flask_endpoints_safe(analysis) or not _python_flask_setup_order_safe(
        analysis,
        mount_edges=mount_edges,
    ):
        return False
    validation = _PythonGraphValidation(
        analysis=analysis,
        imported=imported,
        mount_indexes=frozenset(edge.statement_index for edge in mount_edges),
    )
    for statement_index, statement in enumerate(analysis.tree.body):
        if not _python_graph_statement_safe(
            statement,
            statement_index=statement_index,
            validation=validation,
        ):
            return False
    return True


def _python_flask_endpoints_safe(analysis: _PythonModuleAnalysis) -> bool:
    endpoints: dict[tuple[str, str], int] = {}
    for fragment in analysis.fragments:
        binding = analysis.receivers.get(fragment.receiver_name)
        if binding is None or binding.canonical not in {
            ("flask", "Blueprint"),
            ("flask", "Flask"),
        }:
            continue
        if (
            binding.canonical == ("flask", "Flask")
            and binding.reserves_static_endpoint
            and fragment.endpoint_name == "static"
        ):
            return False
        endpoint = (fragment.receiver_name, fragment.endpoint_name)
        previous_line = endpoints.setdefault(endpoint, fragment.function_line)
        if previous_line != fragment.function_line:
            return False
    return True


def _python_flask_setup_order_safe(
    analysis: _PythonModuleAnalysis,
    *,
    mount_edges: Sequence[_PythonMountEdge],
) -> bool:
    registered_at: dict[str, int] = {}
    for edge in mount_edges:
        if edge.child_id[0] != analysis.source_file:
            continue
        child = analysis.receivers.get(edge.child_id[1])
        if child is None or child.canonical != ("flask", "Blueprint"):
            continue
        registered_at[edge.child_id[1]] = min(
            registered_at.get(edge.child_id[1], edge.declaration_index),
            edge.declaration_index,
        )
    for fragment in analysis.fragments:
        cutoff = registered_at.get(fragment.receiver_name)
        if cutoff is not None and fragment.declaration_index > cutoff:
            return False
    return all(
        not (
            edge.parent_id[0] == analysis.source_file
            and edge.parent_id[1] in registered_at
            and edge.declaration_index > registered_at[edge.parent_id[1]]
        )
        for edge in mount_edges
    )


def _python_package_initializers_safe(
    source_file: str,
    *,
    analysis_by_file: Mapping[str, _PythonModuleAnalysis],
    invalid_paths: frozenset[str],
) -> bool:
    parent = PurePosixPath(source_file).parent
    owner = analysis_by_file.get(source_file)
    omitted_paths = owner.omitted_paths if owner is not None else frozenset()
    initializers = ["__init__.py"]
    initializers.extend(
        str(PurePosixPath(*parent.parts[:depth], "__init__.py"))
        for depth in range(1, len(parent.parts) + 1)
    )
    for initializer in initializers:
        if initializer == source_file:
            continue
        if initializer in omitted_paths or initializer in invalid_paths:
            return False
        analysis = analysis_by_file.get(initializer)
        if analysis is not None and not _python_passive_initializer(analysis.tree):
            return False
    return True


def _python_passive_initializer(tree: ast.Module) -> bool:
    for statement in tree.body:
        if isinstance(statement, ast.Pass):
            continue
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
            continue
        if isinstance(statement, ast.Assign):
            assignment = _python_simple_assignment(statement)
            if (
                assignment is not None
                and _python_passive_assignment_name(assignment[0])
                and _python_passive_value(assignment[1])
            ):
                continue
        if (
            isinstance(statement, ast.ImportFrom)
            and statement.level == 0
            and statement.module == "__future__"
            and all(alias.name != "*" for alias in statement.names)
        ):
            continue
        return False
    return True


def _python_graph_statement_safe(
    statement: ast.stmt,
    *,
    statement_index: int,
    validation: _PythonGraphValidation,
) -> bool:
    if isinstance(statement, (ast.Import, ast.ImportFrom)):
        return _python_graph_import_safe(
            statement,
            imported=validation.imported,
            shadowed_modules=validation.analysis.shadowed_modules,
            framework_modules=frozenset(
                binding.canonical[0]
                for binding in validation.analysis.receivers.values()
                if binding.canonical in _PYTHON_GRAPH_ROOTS | _PYTHON_GRAPH_COMPONENTS
            ),
        )
    if isinstance(statement, (ast.Assign, ast.AnnAssign)):
        return _python_graph_assignment_safe(
            statement,
            receivers=validation.analysis.receivers,
        )
    if isinstance(statement, (ast.AsyncFunctionDef, ast.FunctionDef)):
        return _python_graph_function_safe(
            statement,
            analysis=validation.analysis,
            imported=validation.imported,
        )
    if isinstance(statement, ast.Expr):
        return bool(
            statement_index in validation.mount_indexes or isinstance(statement.value, ast.Constant)
        )
    return isinstance(statement, ast.Pass)


def _python_graph_assignment_safe(
    statement: ast.Assign | ast.AnnAssign,
    *,
    receivers: Mapping[str, _ReceiverBinding],
) -> bool:
    if isinstance(statement, ast.AnnAssign):
        return False
    assignment = _python_simple_assignment(statement)
    if assignment is None:
        return False
    name, value = assignment
    if not _python_passive_assignment_name(name):
        return False
    binding = receivers.get(name)
    if binding is None:
        return _python_passive_value(value)
    return bool(
        isinstance(value, ast.Call)
        and _python_graph_constructor_arguments_safe(
            value,
            canonical=binding.canonical,
        )
    )


def _python_graph_import_safe(
    statement: ast.Import | ast.ImportFrom,
    *,
    imported: Mapping[str, _PythonSymbolReference],
    shadowed_modules: frozenset[str],
    framework_modules: frozenset[str],
) -> bool:
    allowed_modules = {"typing", *framework_modules}
    if any(not _python_passive_assignment_name(name) for name in _python_imported_names(statement)):
        return False
    if isinstance(statement, ast.Import):
        return all(
            alias.name in allowed_modules and alias.name not in shadowed_modules
            for alias in statement.names
        )
    if any(alias.name == "*" for alias in statement.names) or not statement.module:
        return False
    if statement.level == 0:
        if statement.module == "__future__":
            return True
        allowed_names = _PYTHON_GRAPH_FROM_IMPORTS.get(statement.module)
        return bool(
            statement.module in allowed_modules
            and allowed_names is not None
            and statement.module not in shadowed_modules
            and all(alias.name in allowed_names for alias in statement.names)
        )
    return all((alias.asname or alias.name) in imported for alias in statement.names)


def _python_imported_names(statement: ast.Import | ast.ImportFrom) -> set[str]:
    if isinstance(statement, ast.Import):
        return {alias.asname or alias.name.split(".", maxsplit=1)[0] for alias in statement.names}
    return {alias.asname or alias.name for alias in statement.names if alias.name != "*"}


def _python_graph_function_safe(
    function: ast.AsyncFunctionDef | ast.FunctionDef,
    *,
    analysis: _PythonModuleAnalysis,
    imported: Mapping[str, _PythonSymbolReference],
) -> bool:
    if not _python_passive_assignment_name(function.name) or function.type_params:
        return False
    if _python_function_references_receivers(
        function,
        receiver_names=frozenset({*analysis.receivers, *imported}),
    ):
        return False
    fragments = tuple(
        _python_decorator_fragment(
            decorator,
            function=function,
            receiver_bindings=analysis.receivers,
        )
        for decorator in function.decorator_list
    )
    if any(fragment is None for fragment in fragments):
        return False
    defaults = (
        *function.args.defaults,
        *(default for default in function.args.kw_defaults if default is not None),
    )
    if any(not _python_passive_value(default) for default in defaults):
        return False
    if not fragments:
        return (
            _python_function_annotation_requirements(
                function,
                tree=analysis.tree,
                module_stores=analysis.module_stores,
                framework="",
            )
            is not None
        )
    return all(
        fragment is not None
        and _python_route_handler_signature_safe(
            function,
            framework=(analysis.receivers[fragment[0]].canonical or ("", ""))[0],
        )
        and _python_function_annotation_requirements(
            function,
            tree=analysis.tree,
            module_stores=analysis.module_stores,
            framework=(analysis.receivers[fragment[0]].canonical or ("", ""))[0],
        )
        is not None
        for fragment in fragments
    )


def _python_route_handler_signature_safe(
    function: ast.AsyncFunctionDef | ast.FunctionDef,
    *,
    framework: str,
) -> bool:
    if framework == "fastapi":
        return not (function.args.posonlyargs or function.args.vararg or function.args.kwarg)
    if framework != "flask" or isinstance(function, ast.AsyncFunctionDef):
        return False
    required_positional = (
        len(function.args.posonlyargs) + len(function.args.args) - len(function.args.defaults)
    )
    return bool(
        required_positional == 0
        and all(default is not None for default in function.args.kw_defaults)
    )


def _python_function_references_receivers(
    function: ast.AsyncFunctionDef | ast.FunctionDef,
    *,
    receiver_names: frozenset[str],
) -> bool:
    visitor = _PythonReceiverReferenceVisitor(receiver_names)
    for statement in function.body:
        visitor.visit(statement)
    return visitor.found


class _PythonReceiverReferenceVisitor(ast.NodeVisitor):
    def __init__(self, receiver_names: frozenset[str]) -> None:
        self.receiver_names = receiver_names
        self.found = False

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in self.receiver_names:
            self.found = True


def _python_graph_constructor_arguments_safe(
    call: ast.Call,
    *,
    canonical: tuple[str, str] | None,
) -> bool:
    if any(keyword.arg is None for keyword in call.keywords):
        return False
    if canonical == ("fastapi", "FastAPI"):
        return _python_fastapi_root_arguments_safe(call)
    if canonical == ("flask", "Flask"):
        return _python_flask_root_arguments_safe(call)
    return canonical in _PYTHON_GRAPH_COMPONENTS


def _python_constructor_value_safe(value: ast.expr) -> bool:
    return bool(
        _python_passive_value(value) or (isinstance(value, ast.Name) and value.id == "__name__")
    )


def _python_fastapi_root_arguments_safe(call: ast.Call) -> bool:
    if call.args:
        return False
    string_keywords = {
        "description",
        "openapi_prefix",
        "root_path",
        "title",
        "version",
    }
    optional_route_keywords = {
        "docs_url",
        "openapi_url",
        "redoc_url",
        "swagger_ui_oauth2_redirect_url",
    }
    bool_keywords = {
        "debug",
        "redirect_slashes",
        "root_path_in_servers",
        "separate_input_output_schemas",
        "strict_content_type",
    }
    for keyword in call.keywords:
        value = keyword.value
        if keyword.arg in string_keywords:
            valid = bool(
                isinstance(value, ast.Constant)
                and isinstance(value.value, str)
                and (keyword.arg not in {"title", "version"} or value.value)
            )
        elif keyword.arg == "summary":
            valid = isinstance(value, ast.Constant) and (
                value.value is None or isinstance(value.value, str)
            )
        elif keyword.arg in optional_route_keywords:
            valid = _python_optional_route_value(value)
        elif keyword.arg in bool_keywords:
            valid = isinstance(value, ast.Constant) and isinstance(value.value, bool)
        else:
            return False
        if not valid:
            return False
    return True


def _python_optional_route_value(value: ast.expr) -> bool:
    if not isinstance(value, ast.Constant):
        return False
    if value.value is None or value.value == "":
        return True
    return bool(isinstance(value.value, str) and _safe_route(value.value))


def _python_flask_root_arguments_safe(call: ast.Call) -> bool:
    allowed_keywords = {"import_name", "static_folder", "template_folder"}
    if len(call.args) > 1 or any(keyword.arg not in allowed_keywords for keyword in call.keywords):
        return False
    import_names = [keyword.value for keyword in call.keywords if keyword.arg == "import_name"]
    if (call.args and import_names) or (not call.args and len(import_names) != 1):
        return False
    import_name = call.args[0] if call.args else import_names[0]
    if not _python_import_name_supported(import_name):
        return False
    return all(
        _python_flask_root_keyword_safe(keyword)
        for keyword in call.keywords
        if keyword.arg != "import_name"
    )


def _python_flask_root_keyword_safe(keyword: ast.keyword) -> bool:
    value = keyword.value
    if not isinstance(value, ast.Constant) or (
        value.value is not None and not isinstance(value.value, str)
    ):
        return False
    if keyword.arg != "static_folder" or value.value is None:
        return True
    static_name = PurePosixPath(value.value.rstrip("/")).name
    return bool(static_name and _safe_route(f"/{static_name}"))


def _python_import_name_supported(value: ast.expr) -> bool:
    return isinstance(value, ast.Name) and value.id == "__name__"


def _python_passive_value(value: ast.expr) -> bool:
    if isinstance(value, ast.Call):
        return False
    try:
        ast.literal_eval(value)
    except (MemoryError, RecursionError, TypeError, ValueError):
        return False
    return True


def _python_passive_assignment_name(name: str) -> bool:
    return not (name.startswith("__") and name != "__all__")


def _python_function_annotations(
    function: ast.AsyncFunctionDef | ast.FunctionDef,
) -> tuple[ast.expr, ...]:
    annotations = tuple(
        argument.annotation
        for argument in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
        if argument.annotation is not None
    )
    if function.args.vararg is not None and function.args.vararg.annotation is not None:
        annotations += (function.args.vararg.annotation,)
    if function.args.kwarg is not None and function.args.kwarg.annotation is not None:
        annotations += (function.args.kwarg.annotation,)
    if function.returns is not None:
        annotations += (function.returns,)
    return annotations


def _python_function_annotation_requirements(
    function: ast.AsyncFunctionDef | ast.FunctionDef,
    *,
    tree: ast.Module,
    module_stores: Mapping[str, int],
    framework: str,
) -> frozenset[int] | None:
    symbols, modules = _python_annotation_bindings(
        tree,
        module_stores=module_stores,
        before_line=function.lineno,
    )
    requirements: set[int] = set()
    parameter_annotations = tuple(
        argument.annotation
        for argument in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
        if argument.annotation is not None
    )
    if function.args.vararg is not None and function.args.vararg.annotation is not None:
        parameter_annotations += (function.args.vararg.annotation,)
    if function.args.kwarg is not None and function.args.kwarg.annotation is not None:
        parameter_annotations += (function.args.kwarg.annotation,)
    for annotation in parameter_annotations:
        required = _python_annotation_expression_requirements(
            annotation,
            symbols=symbols,
            modules=modules,
            module_stores=module_stores,
            allow_fastapi_request=framework == "fastapi",
        )
        if required is None:
            return None
        requirements.update(required)
    if function.returns is not None:
        required = _python_annotation_expression_requirements(
            function.returns,
            symbols=symbols,
            modules=modules,
            module_stores=module_stores,
            allow_fastapi_request=False,
        )
        if required is None:
            return None
        requirements.update(required)
    return frozenset(requirements)


def _python_annotation_bindings(
    tree: ast.Module,
    *,
    module_stores: Mapping[str, int],
    before_line: int,
) -> tuple[
    dict[str, _PythonAnnotationBinding],
    dict[str, _PythonAnnotationBinding],
]:
    symbols: dict[str, _PythonAnnotationBinding] = {}
    modules: dict[str, _PythonAnnotationBinding] = {}
    for statement in tree.body:
        lines = _node_lines(statement)
        if not lines or max(lines) >= before_line:
            continue
        if (
            isinstance(statement, ast.ImportFrom)
            and statement.level == 0
            and statement.module in {"fastapi", "typing"}
        ):
            for alias in statement.names:
                local_name = alias.asname or alias.name
                if alias.name != "*" and module_stores.get(local_name) == 1:
                    symbols[local_name] = _PythonAnnotationBinding(
                        canonical=(statement.module, alias.name),
                        required_lines=lines,
                    )
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                local_name = alias.asname or alias.name.split(".", maxsplit=1)[0]
                if alias.name in {"fastapi", "typing"} and module_stores.get(local_name) == 1:
                    modules[local_name] = _PythonAnnotationBinding(
                        canonical=(alias.name, ""),
                        required_lines=lines,
                    )
    return symbols, modules


def _python_annotation_expression_requirements(
    annotation: ast.expr,
    *,
    symbols: Mapping[str, _PythonAnnotationBinding],
    modules: Mapping[str, _PythonAnnotationBinding],
    module_stores: Mapping[str, int],
    allow_fastapi_request: bool,
) -> frozenset[int] | None:
    if isinstance(annotation, ast.Constant) and annotation.value is None:
        return frozenset()
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        both_none = all(
            isinstance(operand, ast.Constant) and operand.value is None
            for operand in (annotation.left, annotation.right)
        )
        left = None
        right = None
        if not both_none:
            left = _python_annotation_expression_requirements(
                annotation.left,
                symbols=symbols,
                modules=modules,
                module_stores=module_stores,
                allow_fastapi_request=False,
            )
            right = _python_annotation_expression_requirements(
                annotation.right,
                symbols=symbols,
                modules=modules,
                module_stores=module_stores,
                allow_fastapi_request=False,
            )
        return None if left is None or right is None else left | right
    if isinstance(annotation, ast.Subscript):
        return _python_subscript_annotation_requirements(
            annotation,
            symbols=symbols,
            modules=modules,
            module_stores=module_stores,
            allow_fastapi_request=False,
        )
    binding = _python_annotation_reference(
        annotation,
        symbols=symbols,
        modules=modules,
        module_stores=module_stores,
    )
    if binding is None or binding.canonical not in _PYTHON_ANNOTATION_LEAVES:
        return None
    if binding.canonical == ("fastapi", "Request") and not allow_fastapi_request:
        return None
    return binding.required_lines


def _python_subscript_annotation_requirements(
    annotation: ast.Subscript,
    *,
    symbols: Mapping[str, _PythonAnnotationBinding],
    modules: Mapping[str, _PythonAnnotationBinding],
    module_stores: Mapping[str, int],
    allow_fastapi_request: bool,
) -> frozenset[int] | None:
    binding = _python_annotation_reference(
        annotation.value,
        symbols=symbols,
        modules=modules,
        module_stores=module_stores,
    )
    if binding is None:
        return None
    arity = _PYTHON_ANNOTATION_GENERIC_ARITY.get(binding.canonical)
    if arity is None:
        return None
    arguments = (
        tuple(annotation.slice.elts)
        if isinstance(annotation.slice, ast.Tuple)
        else (annotation.slice,)
    )
    minimum, maximum = arity
    if len(arguments) < minimum or (maximum is not None and len(arguments) > maximum):
        return None
    requirements = set(binding.required_lines)
    for index, argument in enumerate(arguments):
        if isinstance(argument, ast.Constant) and argument.value is Ellipsis:
            if not (
                binding.canonical == ("builtins", "tuple")
                and len(arguments) == _VARIADIC_TUPLE_ARGUMENTS
                and index == 1
            ):
                return None
            continue
        required = _python_annotation_expression_requirements(
            argument,
            symbols=symbols,
            modules=modules,
            module_stores=module_stores,
            allow_fastapi_request=allow_fastapi_request,
        )
        if required is None:
            return None
        requirements.update(required)
    return frozenset(requirements)


def _python_annotation_reference(
    annotation: ast.expr,
    *,
    symbols: Mapping[str, _PythonAnnotationBinding],
    modules: Mapping[str, _PythonAnnotationBinding],
    module_stores: Mapping[str, int],
) -> _PythonAnnotationBinding | None:
    supported_builtins = {
        name
        for module, name in _PYTHON_ANNOTATION_LEAVES | frozenset(_PYTHON_ANNOTATION_GENERIC_ARITY)
        if module == "builtins"
    }
    if isinstance(annotation, ast.Name):
        if annotation.id in supported_builtins and module_stores.get(annotation.id, 0) == 0:
            return _PythonAnnotationBinding(
                canonical=("builtins", annotation.id),
                required_lines=frozenset(),
            )
        return symbols.get(annotation.id)
    if not (
        isinstance(annotation, ast.Attribute)
        and isinstance(annotation.value, ast.Name)
        and annotation.value.id in modules
    ):
        return None
    module = modules[annotation.value.id]
    return _PythonAnnotationBinding(
        canonical=(module.canonical[0], annotation.attr),
        required_lines=module.required_lines,
    )


def _python_mount_edges(
    analysis: _PythonModuleAnalysis,
    *,
    receivers: Mapping[tuple[str, str], _ReceiverBinding],
    imported: Mapping[str, _PythonSymbolReference],
) -> tuple[_PythonMountEdge, ...]:
    local = {
        name: _PythonSymbolReference(
            receiver_id=(analysis.source_file, name),
            required_lines=frozenset(),
            declaration_index=binding.declaration_index,
        )
        for name, binding in analysis.receivers.items()
        if _python_graph_root(binding) or _python_graph_component(binding)
    }
    symbols = {**imported, **local}
    edges: list[_PythonMountEdge] = []
    for statement_index, statement in enumerate(analysis.tree.body):
        edge = _python_mount_edge(
            analysis,
            statement,
            statement_index=statement_index,
            symbols=symbols,
            receivers=receivers,
        )
        if edge is not None:
            edges.append(edge)
    return tuple(edges)


def _python_mount_edge(  # noqa: PLR0911
    analysis: _PythonModuleAnalysis,
    statement: ast.stmt,
    *,
    statement_index: int,
    symbols: Mapping[str, _PythonSymbolReference],
    receivers: Mapping[tuple[str, str], _ReceiverBinding],
) -> _PythonMountEdge | None:
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return None
    call = statement.value
    operation = call.func.attr if isinstance(call.func, ast.Attribute) else ""
    allowed_keywords = (
        {"prefix", "router"} if operation == "include_router" else {"blueprint", "url_prefix"}
    )
    if (
        not isinstance(call.func, ast.Attribute)
        or not isinstance(call.func.value, ast.Name)
        or call.func.attr not in {"include_router", "register_blueprint"}
        or any(keyword.arg is None for keyword in call.keywords)
        or any(keyword.arg not in allowed_keywords for keyword in call.keywords)
    ):
        return None
    parent = symbols.get(call.func.value.id)
    if parent is None or parent.receiver_id[0] != analysis.source_file:
        return None
    child_name = _python_mount_child_name(call, operation=call.func.attr)
    if not child_name or (child := symbols.get(child_name)) is None:
        return None
    if child.receiver_id[0] != analysis.source_file and _python_imported_receiver_mutated(
        analysis.tree, child_name
    ):
        return None
    parent_binding = receivers.get(parent.receiver_id)
    child_binding = receivers.get(child.receiver_id)
    if parent_binding is None or child_binding is None:
        return None
    if not _python_mount_pair_supported(
        operation=call.func.attr,
        parent=parent_binding,
        child=child_binding,
    ):
        return None
    prefix = _python_mount_prefix(call, operation=call.func.attr)
    if prefix is None:
        return None
    registration_prefix, overrides_child_prefix = prefix
    lines = _node_lines(statement) | parent.required_lines | child.required_lines
    if (
        not lines
        or parent.declaration_index >= min(_node_lines(statement))
        or child.declaration_index >= min(_node_lines(statement))
        or len(lines) > _MAX_REQUIRED_LINES
    ):
        return None
    return _PythonMountEdge(
        parent_id=parent.receiver_id,
        child_id=child.receiver_id,
        child_name=child_name,
        registration_prefix=registration_prefix,
        overrides_child_prefix=overrides_child_prefix,
        source_file=analysis.source_file,
        required_lines=lines,
        declaration_index=max(_node_lines(statement)),
        statement_index=statement_index,
    )


def _python_mount_child_name(call: ast.Call, *, operation: str) -> str:
    keyword_name = "router" if operation == "include_router" else "blueprint"
    matching_keywords = [keyword.value for keyword in call.keywords if keyword.arg == keyword_name]
    if len(call.args) == 1 and not matching_keywords:
        child = call.args[0]
    elif not call.args and len(matching_keywords) == 1:
        child = matching_keywords[0]
    else:
        return ""
    return child.id if isinstance(child, ast.Name) else ""


def _python_mount_pair_supported(
    *,
    operation: str,
    parent: _ReceiverBinding,
    child: _ReceiverBinding,
) -> bool:
    if operation == "include_router":
        return bool(
            parent.canonical in {("fastapi", "FastAPI"), ("fastapi", "APIRouter")}
            and child.canonical == ("fastapi", "APIRouter")
        )
    return bool(
        operation == "register_blueprint"
        and parent.canonical in {("flask", "Flask"), ("flask", "Blueprint")}
        and child.canonical == ("flask", "Blueprint")
    )


def _python_mount_prefix(
    call: ast.Call,
    *,
    operation: str,
) -> tuple[str, bool] | None:
    keyword_name = "prefix" if operation == "include_router" else "url_prefix"
    matches = [keyword.value for keyword in call.keywords if keyword.arg == keyword_name]
    if not matches:
        return "", False
    prefix: tuple[str, bool] | None = None
    if len(matches) == 1 and isinstance(matches[0], ast.Constant):
        value = matches[0].value
        flask_override = operation == "register_blueprint"
        if value is None and flask_override:
            prefix = "", False
        elif value == "":
            prefix = "", flask_override
        elif isinstance(value, str) and (flask_override or not value.endswith("/")):
            normalized = value.rstrip("/") if flask_override else value
            safe_prefix = _safe_route(normalized) if normalized else ""
            if safe_prefix:
                prefix = safe_prefix, flask_override
            elif not normalized:
                prefix = "", flask_override
    return prefix


def _walk_python_mount_graph(  # noqa: C901, PLR0913 - bounded graph traversal.
    *,
    receiver_id: tuple[str, str],
    route_prefix: str,
    requirements: Mapping[str, frozenset[int]],
    cutoff: int | None,
    depth: int,
    visited: frozenset[tuple[str, str]],
    receivers: Mapping[tuple[str, str], _ReceiverBinding],
    outgoing: Mapping[tuple[str, str], Sequence[_PythonMountEdge]],
    fragments: Mapping[tuple[str, str], Sequence[_PythonRouteFragment]],
    facts: list[_RouteFact],
) -> None:
    if depth > _MAX_PYTHON_MOUNT_DEPTH or receiver_id in visited:
        return
    binding = receivers.get(receiver_id)
    if binding is None:
        return
    branch_visited = visited | {receiver_id}
    if _python_graph_root(binding) or _python_graph_component(binding):
        for fragment in fragments.get(receiver_id, ()):
            if cutoff is not None and fragment.declaration_index >= cutoff:
                continue
            _append_python_composed_facts(
                fragment,
                route_prefix=route_prefix,
                requirements=requirements,
                facts=facts,
            )
    for edge in outgoing.get(receiver_id, ()):
        if cutoff is not None and edge.declaration_index >= cutoff:
            continue
        child_binding = receivers.get(edge.child_id)
        if child_binding is None:
            continue
        child_segment = (
            edge.registration_prefix
            if edge.overrides_child_prefix
            else _join_python_prefixes(
                edge.registration_prefix,
                child_binding.path_prefix,
            )
        )
        if child_segment is None:
            continue
        child_prefix = _join_python_prefixes(route_prefix, child_segment)
        if child_prefix is None:
            continue
        child_requirements = _merge_python_requirements(
            requirements,
            edge.source_file,
            edge.required_lines,
        )
        if child_requirements is None:
            continue
        child_requirements = _merge_python_requirements(
            child_requirements,
            edge.child_id[0],
            child_binding.required_lines,
        )
        if child_requirements is None:
            continue
        child_cutoff = edge.declaration_index if edge.source_file == edge.child_id[0] else None
        _walk_python_mount_graph(
            receiver_id=edge.child_id,
            route_prefix=child_prefix,
            requirements=child_requirements,
            cutoff=child_cutoff,
            depth=depth + 1,
            visited=branch_visited,
            receivers=receivers,
            outgoing=outgoing,
            fragments=fragments,
            facts=facts,
        )


def _append_python_composed_facts(
    fragment: _PythonRouteFragment,
    *,
    route_prefix: str,
    requirements: Mapping[str, frozenset[int]],
    facts: list[_RouteFact],
) -> None:
    path = _compose_static_route(route_prefix, fragment.path)
    if not path:
        return
    complete = _merge_python_requirements(
        requirements,
        fragment.source_file,
        fragment.required_lines,
    )
    if complete is None:
        return
    primary = complete.get(fragment.source_file, frozenset())
    supporting = tuple(
        _SourceRequirement(source_file, lines)
        for source_file, lines in sorted(complete.items())
        if source_file != fragment.source_file
    )
    facts.extend(
        _RouteFact(
            method=method,
            path=path,
            source_file=fragment.source_file,
            required_lines=primary,
            query_facts=fragment.query_facts,
            supporting_requirements=supporting,
        )
        for method in fragment.methods
    )


def _merge_python_requirements(
    current: Mapping[str, frozenset[int]],
    source_file: str,
    lines: frozenset[int],
) -> dict[str, frozenset[int]] | None:
    merged = dict(current)
    merged[source_file] = merged.get(source_file, frozenset()) | lines
    if (
        len(merged) > _MAX_ROUTE_REQUIREMENT_FILES
        or sum(len(required) for required in merged.values()) > _MAX_ROUTE_REQUIREMENT_LINES
    ):
        return None
    return merged


def _join_python_prefixes(left: str, right: str) -> str | None:
    if not left:
        return right
    if not right:
        return left
    if left == "/" or right == "/":
        return None
    return _safe_route(left.rstrip("/") + right) or None


def _python_receiver_bindings(
    tree: ast.Module,
    *,
    suppress_mounted: bool = True,
) -> dict[str, _ReceiverBinding]:
    constructor_aliases, module_aliases = _python_constructor_aliases(tree.body)
    module_stores = _module_scope_stores(tree)
    attribute_mutations = _python_module_attribute_mutations(tree)
    bindings: dict[str, _ReceiverBinding] = {}
    for statement in _definitely_executed_module_statements(tree.body):
        assignment = _python_simple_assignment(statement)
        if assignment is None:
            continue
        name, value = assignment
        if module_stores.get(name, 0) != 1 or not isinstance(value, ast.Call):
            continue
        if _python_receiver_method_mutated(
            tree,
            name,
        ) or _python_constructor_method_mutated(
            tree,
            value.func,
            attribute_mutations=attribute_mutations,
        ):
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
                name=name,
                required_lines=lines,
                declaration_index=max(assignment_lines),
                path_prefix=prefix,
                canonical=canonical,
                registration_name=_python_blueprint_registration_name(
                    value,
                    canonical=canonical,
                ),
                reserves_static_endpoint=_python_flask_reserves_static_endpoint(
                    value,
                    canonical=canonical,
                ),
                reserved_routes=_python_fastapi_reserved_routes(
                    value,
                    canonical=canonical,
                ),
                reserved_path_prefixes=_python_flask_reserved_path_prefixes(
                    value,
                    canonical=canonical,
                ),
                redirect_slashes=_python_fastapi_redirect_slashes(
                    value,
                    canonical=canonical,
                ),
            )
    if not suppress_mounted:
        return bindings
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
        if isinstance(statement, ast.ImportFrom) and statement.level == 0 and statement.module:
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


def _python_static_route_prefix(call: ast.Call, *, canonical: tuple[str, str]) -> str | None:
    constructor = canonical[1]
    keyword_names = [keyword.arg for keyword in call.keywords if keyword.arg is not None]
    if len(keyword_names) != len(set(keyword_names)):
        return None
    if constructor not in {"APIRouter", "Blueprint"}:
        return ""
    if canonical in _PYTHON_GRAPH_COMPONENTS and not _python_component_arguments_supported(
        call,
        canonical=canonical,
    ):
        return None
    prefix_name = "prefix" if constructor == "APIRouter" else "url_prefix"
    matches = [keyword.value for keyword in call.keywords if keyword.arg == prefix_name]
    if not matches:
        return ""
    if len(matches) != 1:
        return None
    return _python_static_component_prefix(
        matches[0],
        normalize_slash=canonical == ("flask", "Blueprint"),
        allow_none=canonical == ("flask", "Blueprint"),
    )


def _python_component_arguments_supported(
    call: ast.Call,
    *,
    canonical: tuple[str, str],
) -> bool:
    if any(keyword.arg is None for keyword in call.keywords):
        return False
    if canonical == ("fastapi", "APIRouter"):
        return bool(not call.args and all(keyword.arg == "prefix" for keyword in call.keywords))
    if any(keyword.arg not in {"import_name", "name", "url_prefix"} for keyword in call.keywords):
        return False
    return bool(
        _python_blueprint_arguments_supported(call)
        and _python_blueprint_identity_values_supported(call)
    )


def _python_static_component_prefix(
    value: ast.expr,
    *,
    normalize_slash: bool = False,
    allow_none: bool = False,
) -> str | None:
    if not isinstance(value, ast.Constant):
        return None
    if value.value is None:
        return "" if allow_none else None
    if not isinstance(value.value, str):
        return None
    return _python_normalized_component_prefix(
        value.value,
        normalize_slash=normalize_slash,
    )


def _python_normalized_component_prefix(
    value: str,
    *,
    normalize_slash: bool,
) -> str | None:
    if value.endswith("/") and not normalize_slash:
        return None
    normalized = value.rstrip("/") if normalize_slash else value
    if not normalized:
        return ""
    return _safe_route(normalized) or None


def _python_blueprint_arguments_supported(call: ast.Call) -> bool:
    if len(call.args) > _MIN_ROUTE_ARGUMENTS:
        return False
    keyword_names = {keyword.arg for keyword in call.keywords}
    positional_name = len(call.args) >= 1
    positional_import_name = len(call.args) >= _MIN_ROUTE_ARGUMENTS
    if (positional_name and "name" in keyword_names) or (
        positional_import_name and "import_name" in keyword_names
    ):
        return False
    return bool(
        (positional_name or "name" in keyword_names)
        and (positional_import_name or "import_name" in keyword_names)
    )


def _python_blueprint_identity_values_supported(call: ast.Call) -> bool:
    named = {keyword.arg: keyword.value for keyword in call.keywords}
    name = call.args[0] if call.args else named.get("name")
    import_name = (
        call.args[1] if len(call.args) >= _MIN_ROUTE_ARGUMENTS else named.get("import_name")
    )
    return bool(
        isinstance(name, ast.Constant)
        and isinstance(name.value, str)
        and name.value
        and "." not in name.value
        and import_name is not None
        and _python_import_name_supported(import_name)
    )


def _python_blueprint_registration_name(
    call: ast.Call,
    *,
    canonical: tuple[str, str],
) -> str:
    if canonical != ("flask", "Blueprint"):
        return ""
    named = {keyword.arg: keyword.value for keyword in call.keywords}
    value = call.args[0] if call.args else named.get("name")
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else ""


def _python_flask_reserves_static_endpoint(
    call: ast.Call,
    *,
    canonical: tuple[str, str],
) -> bool:
    if canonical != ("flask", "Flask"):
        return False
    static_folder = next(
        (keyword.value for keyword in call.keywords if keyword.arg == "static_folder"),
        None,
    )
    return not (isinstance(static_folder, ast.Constant) and static_folder.value is None)


def _python_flask_reserved_path_prefixes(
    call: ast.Call,
    *,
    canonical: tuple[str, str],
) -> frozenset[tuple[str, str]]:
    if canonical != ("flask", "Flask") or not _python_flask_reserves_static_endpoint(
        call,
        canonical=canonical,
    ):
        return frozenset()
    static_folder = next(
        (keyword.value for keyword in call.keywords if keyword.arg == "static_folder"),
        None,
    )
    path = "/static"
    if isinstance(static_folder, ast.Constant) and isinstance(static_folder.value, str):
        static_name = PurePosixPath(static_folder.value.rstrip("/")).name
        path = f"/{static_name}"
    return frozenset((method, path) for method in ("GET", "HEAD", "OPTIONS"))


def _python_fastapi_reserved_routes(
    call: ast.Call,
    *,
    canonical: tuple[str, str],
) -> frozenset[tuple[str, str]]:
    if canonical != ("fastapi", "FastAPI"):
        return frozenset()
    values: dict[str, object] = {
        "openapi_url": "/openapi.json",
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "swagger_ui_oauth2_redirect_url": "/docs/oauth2-redirect",
    }
    for keyword in call.keywords:
        if keyword.arg in values and isinstance(keyword.value, ast.Constant):
            values[keyword.arg] = keyword.value.value
    openapi_url = values["openapi_url"]
    if not isinstance(openapi_url, str) or not openapi_url:
        return frozenset()
    paths = {openapi_url}
    docs_url = values["docs_url"]
    if isinstance(docs_url, str) and docs_url:
        paths.add(docs_url)
        oauth_url = values["swagger_ui_oauth2_redirect_url"]
        if isinstance(oauth_url, str) and oauth_url:
            paths.add(oauth_url)
    redoc_url = values["redoc_url"]
    if isinstance(redoc_url, str) and redoc_url:
        paths.add(redoc_url)
    return frozenset((method, path) for path in paths for method in ("GET", "HEAD"))


def _python_fastapi_redirect_slashes(
    call: ast.Call,
    *,
    canonical: tuple[str, str],
) -> bool:
    if canonical != ("fastapi", "FastAPI"):
        return True
    value = next(
        (keyword.value for keyword in call.keywords if keyword.arg == "redirect_slashes"),
        None,
    )
    return not (isinstance(value, ast.Constant) and value.value is False)


def _python_receiver_method_mutated(tree: ast.Module, receiver: str) -> bool:
    visitor = _PythonMemberMutationVisitor(_python_receiver_alias_names(tree, receiver))
    for statement in tree.body:
        visitor.visit(statement)
    return visitor.mutated


def _python_constructor_method_mutated(
    tree: ast.Module,
    function: ast.expr,
    *,
    attribute_mutations: frozenset[tuple[str, str]],
) -> bool:
    if not isinstance(function, ast.Name):
        return False
    constructor_names = _python_receiver_alias_names(tree, function.id)
    return any(receiver in constructor_names for receiver, _attribute in attribute_mutations)


def _python_receiver_alias_names(tree: ast.Module, receiver: str) -> frozenset[str]:
    aliases = {receiver}
    module_stores = _module_scope_stores(tree)
    for statement in _reachable_module_statements(tree.body):
        assignment = _python_simple_assignment(statement)
        if assignment is None:
            continue
        name, value = assignment
        if isinstance(value, ast.Name) and value.id in aliases and module_stores.get(name) == 1:
            aliases.add(name)
    return frozenset(aliases)


class _PythonMemberMutationVisitor(ast.NodeVisitor):
    def __init__(self, receivers: frozenset[str]) -> None:
        self.receivers = receivers
        self.mutated = False

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if (
            isinstance(node.ctx, (ast.Del, ast.Store))
            and isinstance(node.value, ast.Name)
            and node.value.id in self.receivers
            and node.attr
            in {
                "api_route",
                "get",
                "head",
                "include_router",
                "options",
                "register_blueprint",
                "route",
            }
        ):
            self.mutated = True

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"delattr", "setattr"}
            and len(node.args) >= _MIN_ROUTE_ARGUMENTS
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in self.receivers
            and _python_string(node.args[1])
            in {
                "api_route",
                "get",
                "head",
                "include_router",
                "options",
                "register_blueprint",
                "route",
            }
        ):
            self.mutated = True
        self.generic_visit(node)


def _python_imported_receiver_mutated(tree: ast.Module, receiver: str) -> bool:
    visitor = _PythonImportedReceiverMutationVisitor(_python_receiver_alias_names(tree, receiver))
    for statement in tree.body:
        visitor.visit(statement)
    return visitor.mutated


class _PythonImportedReceiverMutationVisitor(ast.NodeVisitor):
    def __init__(self, receivers: frozenset[str]) -> None:
        self.receivers = receivers
        self.mutated = False

    def visit_Attribute(self, node: ast.Attribute) -> None:
        root, _operation = _python_attribute_parts(node)
        if isinstance(node.ctx, (ast.Del, ast.Store)) and root[:1] and root[0] in self.receivers:
            self.mutated = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        root, _operation = _python_attribute_parts(node.func)
        if root[:1] and root[0] in self.receivers:
            self.mutated = True
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"delattr", "setattr"}
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in self.receivers
        ):
            self.mutated = True
        self.generic_visit(node)

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


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

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.counts[node.name] = self.counts.get(node.name, 0) + 1
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self.counts[node.name] = self.counts.get(node.name, 0) + 1
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self.counts[node.name] = self.counts.get(node.name, 0) + 1

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.counts[node.rest] = self.counts.get(node.rest, 0) + 1
        self.generic_visit(node)

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


def _definitely_executed_module_statements(
    statements: Sequence[ast.stmt],
) -> tuple[ast.stmt, ...]:
    definite: list[ast.stmt] = []
    for statement in statements:
        definite.append(statement)
        if not isinstance(statement, ast.If):
            continue
        truth = _python_static_truth(statement.test)
        if truth is None:
            continue
        branch = statement.body if truth else statement.orelse
        definite.extend(_definitely_executed_module_statements(branch))
    return tuple(definite)


def _definitely_executed_module_functions(
    statements: Sequence[ast.stmt],
) -> tuple[ast.AsyncFunctionDef | ast.FunctionDef, ...]:
    return tuple(
        statement
        for statement in _definitely_executed_module_statements(statements)
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


def _python_decorator_fragment(  # noqa: PLR0911
    decorator: ast.expr,
    *,
    function: ast.AsyncFunctionDef | ast.FunctionDef,
    receiver_bindings: Mapping[str, _ReceiverBinding],
) -> tuple[str, frozenset[str], frozenset[str], str, frozenset[int]] | None:
    if not isinstance(decorator, ast.Call) or len(decorator.args) != 1:
        return None
    receiver, operation = _python_attribute_parts(decorator.func)
    if len(receiver) != 1 or receiver[0] not in receiver_bindings:
        return None
    binding = receiver_bindings[receiver[0]]
    if operation not in _python_route_operations(binding.canonical):
        return None
    keyword_names = [keyword.arg for keyword in decorator.keywords]
    allowed_keywords = {"methods"} if operation in {"api_route", "route"} else set()
    if any(name is None or name not in allowed_keywords for name in keyword_names) or len(
        keyword_names
    ) != len(set(keyword_names)):
        return None
    decorator_lines = _node_lines(decorator)
    if not decorator_lines or binding.declaration_index >= min(decorator_lines):
        return None
    literal = decorator.args[0]
    if not isinstance(literal, ast.Constant) or not isinstance(literal.value, str):
        return None
    path = _safe_route(literal.value)
    if not path:
        return None
    declared_methods = _python_declared_route_methods(decorator, operation=operation)
    if not declared_methods:
        return None
    methods = frozenset(declared_methods & {"GET", "HEAD", "OPTIONS"})
    occupied_methods = _python_occupied_route_methods(
        declared_methods,
        canonical=binding.canonical,
    )
    lines = decorator_lines | binding.required_lines | _python_function_header_lines(function)
    if not lines:
        return None
    return receiver[0], methods, occupied_methods, path, lines


def _python_route_operations(canonical: tuple[str, str] | None) -> frozenset[str]:
    if canonical in {
        ("fastapi", "APIRouter"),
        ("fastapi", "FastAPI"),
    }:
        return frozenset({"api_route", "get", "head", "options"})
    if canonical in {
        ("flask", "Blueprint"),
        ("flask", "Flask"),
    }:
        return frozenset({"get", "route"})
    return frozenset()


def _python_function_header_lines(
    function: ast.AsyncFunctionDef | ast.FunctionDef,
) -> frozenset[int]:
    first_body_line = min(
        (getattr(statement, "lineno", function.lineno + 1) for statement in function.body),
        default=function.lineno + 1,
    )
    return frozenset(range(function.lineno, max(function.lineno, first_body_line - 1) + 1))


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


def _python_occupied_route_methods(
    declared_methods: frozenset[str],
    *,
    canonical: tuple[str, str] | None,
) -> frozenset[str]:
    methods = set(declared_methods)
    if canonical in {("flask", "Blueprint"), ("flask", "Flask")}:
        if "GET" in methods:
            methods.add("HEAD")
        methods.add("OPTIONS")
    return frozenset(methods & {"GET", "HEAD", "OPTIONS"})


def _python_declared_route_methods(
    decorator: ast.Call,
    *,
    operation: str,
) -> frozenset[str]:
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
    supported = {"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"}
    methods = {
        item.value.upper()
        for item in methods_keyword.elts
        if isinstance(item, ast.Constant)
        and isinstance(item.value, str)
        and item.value.upper() in supported
    }
    return frozenset(methods) if len(methods) == len(methods_keyword.elts) else frozenset()


def _python_query_bindings(
    tree: ast.Module,
    *,
    module_stores: Mapping[str, int],
) -> dict[str, _PythonQueryBinding]:
    candidates: dict[str, list[_PythonQueryBinding]] = {}
    for statement in tree.body:
        if not (
            isinstance(statement, ast.ImportFrom)
            and statement.level == 0
            and statement.module == "flask"
        ):
            continue
        for alias in statement.names:
            local_name = alias.asname or alias.name
            root = local_name
            lines = _node_lines(statement)
            if alias.name == "request" and module_stores.get(local_name) == 1 and lines:
                candidates.setdefault(root, []).append(
                    _PythonQueryBinding(
                        framework=statement.module,
                        required_lines=lines,
                    )
                )
    return {root: matches[0] for root, matches in candidates.items() if len(matches) == 1}


def _python_query_facts(
    function: ast.AsyncFunctionDef | ast.FunctionDef,
    *,
    query_roots: frozenset[str],
) -> tuple[_QueryFact, ...]:
    visitor = _PythonQueryVisitor(
        _python_local_bindings(function, query_roots=query_roots),
        query_roots=query_roots,
    )
    visitor.visit_block(function.body)
    return tuple(sorted(visitor.found, key=lambda fact: (fact.line, fact.name)))


class _PythonQueryVisitor(ast.NodeVisitor):
    def __init__(
        self,
        shadowed_roots: frozenset[str],
        *,
        query_roots: frozenset[str],
    ) -> None:
        self.found: set[_QueryFact] = set()
        self.shadowed_roots = shadowed_roots
        self.query_roots = query_roots

    def visit_block(self, statements: Sequence[ast.stmt]) -> None:
        for statement in statements:
            self.visit(statement)
            if _python_statement_always_terminates(statement):
                break

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node, ast.Call) and node.args and isinstance(node.func, ast.Attribute):
            if node.func.attr != "get":
                self.generic_visit(node)
                return
            root = _python_query_container(
                node.func.value,
                shadowed_roots=self.shadowed_roots,
                query_roots=self.query_roots,
            )
            if root:
                name = _python_string(node.args[0])
                if name and _safe_query_name(name):
                    self.found.add(_QueryFact(name=name, line=node.lineno, root=root))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        root = _python_query_container(
            node.value,
            shadowed_roots=self.shadowed_roots,
            query_roots=self.query_roots,
        )
        if root:
            name = _python_string(node.slice)
            if name and _safe_query_name(name):
                self.found.add(_QueryFact(name=name, line=node.lineno, root=root))
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        for value in node.values:
            self.visit(value)
            truth = _python_static_truth(value)
            if (isinstance(node.op, ast.And) and truth is False) or (
                isinstance(node.op, ast.Or) and truth is True
            ):
                break

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.visit(node.test)
        truth = _python_static_truth(node.test)
        if truth is True:
            self.visit(node.body)
        elif truth is False:
            self.visit(node.orelse)
        else:
            self.visit(node.body)
            self.visit(node.orelse)

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

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        if _python_static_iterable_empty(node.iter) is True:
            self.visit_block(node.orelse)
            return
        self.visit_block(node.body)
        self.visit_block(node.orelse)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit(node.iter)

    def visit_While(self, node: ast.While) -> None:
        if _python_static_truth(node.test) is False:
            self.visit_block(node.orelse)
            return
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self.visit_block(node.body)
        self.visit_block(node.finalbody)

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self.visit_block(node.body)
        self.visit_block(node.finalbody)

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)

    def visit_Compare(self, node: ast.Compare) -> None:
        self.visit(node.left)
        left = node.left
        for operation, right in zip(node.ops, node.comparators, strict=True):
            self.visit(right)
            if _python_static_comparison(left, operation, right) is False:
                break
            left = right

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self.visit(node.generators[0].iter)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self.visit(node.generators[0].iter)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self.visit(node.generators[0].iter)

    def visit_GeneratorExp(self, _node: ast.GeneratorExp) -> None:
        return

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
    *,
    query_roots: frozenset[str],
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
    return frozenset(visitor.names & query_roots)


class _PythonLocalBindingVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Del, ast.Store)):
            self.names.add(node.id)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.names.add(alias.asname or alias.name.split(".", maxsplit=1)[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                self.names.add(alias.asname or alias.name)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self.names.add(node.name)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.names.add(node.rest)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.names.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

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
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        return _python_static_comparison(node.left, node.ops[0], node.comparators[0])
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


def _python_static_comparison(
    left_node: ast.expr,
    operation: ast.cmpop,
    right_node: ast.expr,
) -> bool | None:
    left = _python_static_scalar(left_node)
    right = _python_static_scalar(right_node)
    if left is _UNKNOWN_STATIC_VALUE or right is _UNKNOWN_STATIC_VALUE:
        return None
    if isinstance(operation, ast.Is):
        return (
            left is right if left in {None, True, False} and right in {None, True, False} else None
        )
    if isinstance(operation, ast.IsNot):
        return (
            left is not right
            if left in {None, True, False} and right in {None, True, False}
            else None
        )
    comparisons: dict[type[ast.cmpop], Callable[..., object]] = {
        ast.Eq: operator.eq,
        ast.NotEq: operator.ne,
        ast.Lt: operator.lt,
        ast.LtE: operator.le,
        ast.Gt: operator.gt,
        ast.GtE: operator.ge,
    }
    compare = comparisons.get(type(operation))
    if compare is None:
        return None
    try:
        return bool(compare(left, right))
    except (TypeError, ValueError):
        return None


def _python_static_iterable_empty(node: ast.expr) -> bool | None:
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        return not node.elts
    if isinstance(node, ast.Dict):
        return not node.keys
    if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, str)):
        return not node.value
    return None


def _python_statement_always_terminates(statement: ast.stmt) -> bool:
    if isinstance(statement, (ast.Break, ast.Continue, ast.Raise, ast.Return)):
        return True
    if isinstance(statement, ast.While):
        return bool(
            _python_static_truth(statement.test) is True
            and not _python_loop_has_break(statement.body)
        )
    if not isinstance(statement, ast.If):
        return False
    truth = _python_static_truth(statement.test)
    if truth is True:
        return _python_block_always_terminates(statement.body)
    if truth is False:
        return _python_block_always_terminates(statement.orelse)
    return bool(
        statement.orelse
        and _python_block_always_terminates(statement.body)
        and _python_block_always_terminates(statement.orelse)
    )


def _python_block_always_terminates(statements: Sequence[ast.stmt]) -> bool:
    return any(_python_statement_always_terminates(statement) for statement in statements)


def _python_loop_has_break(statements: Sequence[ast.stmt]) -> bool:
    visitor = _PythonLoopBreakVisitor()
    for statement in statements:
        visitor.visit(statement)
    return visitor.found


class _PythonLoopBreakVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.found = False

    def visit_Break(self, _node: ast.Break) -> None:
        self.found = True

    def visit_For(self, _node: ast.For) -> None:
        return

    def visit_AsyncFor(self, _node: ast.AsyncFor) -> None:
        return

    def visit_While(self, _node: ast.While) -> None:
        return

    def visit_FunctionDef(self, _node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, _node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, _node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, _node: ast.Lambda) -> None:
        return


def _python_query_container(
    node: ast.expr,
    *,
    shadowed_roots: frozenset[str],
    query_roots: frozenset[str],
) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    parts.reverse()
    matched = bool(
        parts
        and parts[0] in query_roots
        and parts[0] not in shadowed_roots
        and tuple(parts[1:]) == ("args",)
    )
    return parts[0] if matched else ""


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
    if any(
        token.value == "throw" and depth == 0
        for token, depth in zip(tokens, _script_brace_depths(tokens), strict=True)
    ):
        return []
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
        elif token.value in pairs and (not stack or stack.pop() != pairs[token.value]):
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


def _script_parenthesized_tokens_valid(tokens: Sequence[_Token], opening: int) -> bool:
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
    if any(commas[index] + 1 == commas[index + 1] for index in range(len(commas) - 1)):
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


def _script_binding_equals(tokens: Sequence[_Token], start: int) -> int | None:
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
            {token.line for token in tokens[index : expression_end + 1]} | set(constructor_lines)
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
        or tokens[index].value != "const"
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


def _module_constructor_alias(tokens: Sequence[_Token], index: int) -> tuple[str, str, int] | None:
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
            and tokens[call_opening + 1].value == ")"
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
        or start + 5 >= end
        or tokens[start].value != "require"
        or tokens[start + 1].value != "("
        or tokens[start + 2].kind != "string"
        or tokens[start + 3].value != ")"
        or tokens[start + 4].value != "("
        or _matching_symbol(tokens, start + 4, "(", ")") != end - 1
        or tokens[start + 5].value != ")"
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
            and token.value not in {"catch", "for", "if", "switch", "while", "with"}
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
    elif start + 2 < end and tokens[start].kind == "identifier" and tokens[start + 1].value == "=>":
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
        required = alias.required_lines | frozenset({tokens[index].line, tokens[body[0]].line})
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
        if name and package in packages and _script_declaration_ends(tokens, end):
            candidates.setdefault(name, []).append(
                _ConstructorAlias(
                    "server",
                    frozenset(token.line for token in tokens[index : end + 1]),
                    declaration_index,
                )
            )
    return {name: items[0] for name, items in candidates.items() if len(items) == 1}


def _script_callback_first_parameter(tokens: Sequence[_Token], *, body_start: int) -> str:
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
            closing - 1 if closing is not None and tokens[closing - 1].value == "," else closing
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
                method=method,
                path=path,
                source_file=source_file,
                required_lines=required,
                query_facts=_queries_in_call(
                    tokens,
                    function_bodies,
                    index + 3,
                    closing,
                    queries,
                ),
                owner=("script", source_file, receiver.value),
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
        arrows = [index for index in range(opening + 1, closing) if tokens[index].value == "=>"]
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
        required = frozenset(use_lines | method_lines) | callback.required_lines | receiver_lines
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
                method="GET",
                path=path,
                source_file=source_file,
                required_lines=required,
                query_facts=_queries_in_if_branch(
                    tokens,
                    index,
                    queries,
                    callback=callback,
                    function_bodies=function_bodies,
                ),
                owner=("script-native", source_file, str(callback.body_start)),
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


def _enclosing_if_condition(tokens: Sequence[_Token], route_index: int) -> tuple[int, int] | None:
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


def _script_expression_is_statically_dead(tokens: Sequence[_Token], index: int) -> bool:
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
        or (tokens[start].kind == "identifier" and tokens[start].value in false_constants)
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


def _matching_symbol(tokens: Sequence[_Token], opening: int, left: str, right: str) -> int | None:
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
            character.isspace()
            or ord(character) < _ASCII_CONTROL_BOUND
            or _UNICODE_SURROGATE_START <= ord(character) <= _UNICODE_SURROGATE_END
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
