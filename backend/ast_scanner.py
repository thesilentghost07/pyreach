"""
backend/ast_scanner.py
~~~~~~~~~~~~~~~~~~~~~~
Static AST scanner for PyReach — Python Vulnerability Reachability Analyzer.

Provides ``scan_project_ast(project_dir)`` which recursively parses every
``*.py`` file in a project tree and extracts imports, function definitions,
call-sites (with alias expansion), and dynamic-reflection hazards into a
deterministic ``ProjectASTResult`` data structure.

Safety: target files are **never** imported or executed. All analysis is
performed via ``ast.parse()`` on UTF-8 text.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Dict, List, Optional, Set

from backend.schemas import (
    CallSite,
    FunctionDefRecord,
    ImportRecord,
    ParsedFile,
    ProjectASTResult,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Directory names that are always skipped during recursive walk.
_SKIP_DIRS: Set[str] = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        "dist",
        "build",
    }
)

#: Function names that are automatically marked as entry points.
_ENTRY_POINT_NAMES: Set[str] = frozenset(
    {"main", "cli", "run", "handler", "lambda_handler", "app"}
)

#: Decorator *base* names that mark a function as an entry point (e.g.
#: ``@app.get("/items")``, ``@click.command``).
_ENTRY_POINT_DECORATORS: Set[str] = frozenset(
    {"get", "post", "put", "delete", "patch", "route", "command", "task"}
)

#: Callees whose presence signals dynamic reflection / execution.
_DYNAMIC_CALLEES: Set[str] = frozenset(
    {
        "getattr",
        "eval",
        "exec",
        "__import__",
        "importlib.import_module",
        "globals",
        "locals",
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _collect_python_files(project_dir: Path) -> List[Path]:
    """Return a deterministically-sorted list of ``*.py`` files under
    *project_dir*, excluding common non-source directories."""
    result: List[Path] = []
    for root_str, dirs, files in os.walk(project_dir, topdown=True):
        # Prune skipped directories **in-place** so os.walk won't descend.
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        root = Path(root_str)
        for fname in sorted(files):
            if fname.endswith(".py"):
                result.append(root / fname)
    return result


def _rel_path_to_module_prefix(rel: Path) -> str:
    """Convert a relative ``.py`` path to a dotted module prefix.

    Examples::

        main.py         -> "main"
        app/utils.py    -> "app.utils"
        app/__init__.py -> "app"
    """
    parts = list(rel.parts)
    # Strip the .py extension from the last component.
    stem = parts[-1][: -len(".py")]
    if stem == "__init__":
        parts = parts[:-1]
    else:
        parts[-1] = stem
    return ".".join(parts) if parts else "__init__"


def _extract_callee_name(node: ast.expr) -> Optional[str]:
    """Best-effort extraction of a dotted callee string from an AST node.

    Returns ``None`` for compound expressions that cannot be expressed as a
    simple dotted name (subscripts, call results, lambdas, …).
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _extract_callee_name(node.value)
        if parent is not None:
            return f"{parent}.{node.attr}"
    return None


def _has_entry_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return ``True`` if any decorator is (or ends with) a known route/CLI
    decorator name."""
    for dec in node.decorator_list:
        # @app.post("/scan") -> ast.Call whose func is ast.Attribute
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute) and target.attr in _ENTRY_POINT_DECORATORS:
            return True
        if isinstance(target, ast.Name) and target.id in _ENTRY_POINT_DECORATORS:
            return True
    return False


# ---------------------------------------------------------------------------
# AST Visitor
# ---------------------------------------------------------------------------


class _FileASTVisitor(ast.NodeVisitor):
    """Walk a single file's AST and collect imports, function defs, and
    call-sites with alias expansion and dynamic-call detection."""

    def __init__(self, module_prefix: str, rel_str: str) -> None:
        self.module_prefix = module_prefix
        self.rel_str = rel_str

        # Collected records
        self.imports: List[ImportRecord] = []
        self.functions: List[FunctionDefRecord] = []
        self.calls: List[CallSite] = []

        # Name resolution state
        self.alias_map: Dict[str, str] = {}
        self.scope_stack: List[str] = [f"{module_prefix}.<module>"]
        self.class_stack: List[str] = []

        # Set of locally defined function names (simple, unqualified)
        self._local_func_names: Set[str] = set()

    # -- helpers ----------------------------------------------------------

    @property
    def _current_scope(self) -> str:
        return self.scope_stack[-1]

    def _resolve_relative_import(self, level: int, module: Optional[str]) -> str:
        """Resolve a relative import (``from .foo import bar``) against the
        current *module_prefix*."""
        parts = self.module_prefix.split(".")
        # Go up `level` packages (at least keep an empty root).
        base_parts = parts[: max(0, len(parts) - level)]
        base = ".".join(base_parts) if base_parts else ""
        if module:
            return f"{base}.{module}" if base else module
        return base

    # -- visitors ---------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            bound = alias.asname if alias.asname else alias.name
            self.alias_map[bound] = alias.name
            self.imports.append(
                ImportRecord(
                    module=alias.name,
                    imported_name=None,
                    alias=bound,
                    file=self.rel_str,
                    line=node.lineno,
                )
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.level and node.level > 0:
            base_mod = self._resolve_relative_import(node.level, node.module)
        else:
            base_mod = node.module or ""

        for alias in node.names:
            bound = alias.asname if alias.asname else alias.name

            if alias.name == "*":
                # Wildcard import — record + flag dynamic hazard.
                self.imports.append(
                    ImportRecord(
                        module=base_mod,
                        imported_name="*",
                        alias="*",
                        file=self.rel_str,
                        line=node.lineno,
                    )
                )
                self.calls.append(
                    CallSite(
                        caller_qualname=self._current_scope,
                        raw_callee=f"{base_mod}.*",
                        resolved_callee=None,
                        file=self.rel_str,
                        line=node.lineno,
                        is_dynamic=True,
                        dynamic_reason=(
                            f"Wildcard import 'from {base_mod} import *' "
                            f"at {self.rel_str}:{node.lineno}"
                        ),
                    )
                )
            else:
                fqn = f"{base_mod}.{alias.name}" if base_mod else alias.name
                self.alias_map[bound] = fqn
                self.imports.append(
                    ImportRecord(
                        module=base_mod,
                        imported_name=alias.name,
                        alias=bound,
                        file=self.rel_str,
                        line=node.lineno,
                    )
                )
        self.generic_visit(node)

    # -- function / method definitions ------------------------------------

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if self.class_stack:
            qualname = (
                f"{self.module_prefix}."
                f"{'.'.join(self.class_stack)}.{node.name}"
            )
        else:
            qualname = f"{self.module_prefix}.{node.name}"

        is_entry = (
            node.name in _ENTRY_POINT_NAMES or _has_entry_decorator(node)
        )

        self.functions.append(
            FunctionDefRecord(
                qualname=qualname,
                name=node.name,
                file=self.rel_str,
                line=node.lineno,
                is_entry_point=is_entry,
            )
        )
        self._local_func_names.add(node.name)

        # Push scope, visit body, pop scope.
        self.scope_stack.append(qualname)
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    # -- class definitions ------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    # -- call-sites -------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        raw = _extract_callee_name(node.func)
        is_dynamic = False
        dynamic_reason: Optional[str] = None

        if raw is None:
            raw = "<expr>"
            is_dynamic = True
            dynamic_reason = (
                f"Dynamic/computed call expression at "
                f"{self.rel_str}:{node.lineno}"
            )

        # --- Alias expansion / resolution --------------------------------
        resolved: Optional[str] = None

        if raw.startswith("self.") and self.class_stack:
            tail = raw[len("self."):]
            resolved = (
                f"{self.module_prefix}."
                f"{'.'.join(self.class_stack)}.{tail}"
            )
        else:
            root = raw.split(".")[0]
            if root in self.alias_map:
                resolved = self.alias_map[root] + raw[len(root):]

        # --- Dynamic reflection detection --------------------------------
        check_name = resolved or raw
        if check_name in _DYNAMIC_CALLEES or raw in _DYNAMIC_CALLEES:
            is_dynamic = True
            dynamic_reason = (
                f"Dynamic reflection/execution call '{raw}()' "
                f"at {self.rel_str}:{node.lineno}"
            )

        self.calls.append(
            CallSite(
                caller_qualname=self._current_scope,
                raw_callee=raw,
                resolved_callee=resolved,
                file=self.rel_str,
                line=node.lineno,
                is_dynamic=is_dynamic,
                dynamic_reason=dynamic_reason,
            )
        )

        # IMPORTANT: recurse into child nodes so nested calls are captured
        # (e.g. ``print(sanitize(yaml.load(raw)))``).
        self.generic_visit(node)

    # -- post-pass: resolve intra-file calls ------------------------------

    def finalize_local_calls(self) -> None:
        """Second pass: if a call's *resolved_callee* is still ``None`` and
        its *raw_callee* matches a locally defined function name, resolve it
        to ``<module_prefix>.<raw_callee>``."""
        for cs in self.calls:
            if cs.resolved_callee is None and cs.raw_callee in self._local_func_names:
                cs.resolved_callee = f"{self.module_prefix}.{cs.raw_callee}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_project_ast(project_dir: Path) -> ProjectASTResult:
    """Scan *project_dir* and return a ``ProjectASTResult`` with all parsed
    files, imports, function definitions, call-sites, and entry points.

    Target files are **never** imported or executed — all analysis is purely
    static via ``ast.parse()``.
    """
    project_dir = Path(project_dir).resolve()
    py_files = _collect_python_files(project_dir)

    parsed_files: List[ParsedFile] = []
    all_entry_points: List[str] = []

    for abs_path in py_files:
        rel = abs_path.relative_to(project_dir)
        rel_str = str(rel)
        module_prefix = _rel_path_to_module_prefix(rel)

        # -- Fault-tolerant read + parse ----------------------------------
        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=rel_str)
        except (SyntaxError, UnicodeDecodeError, OSError) as exc:
            parsed_files.append(
                ParsedFile(file_path=rel_str, parse_error=str(exc))
            )
            continue

        # -- Seed the module-level entry point ----------------------------
        module_ep = FunctionDefRecord(
            qualname=f"{module_prefix}.<module>",
            name="<module>",
            file=rel_str,
            line=1,
            is_entry_point=True,
        )

        # -- Walk the AST ------------------------------------------------
        visitor = _FileASTVisitor(module_prefix, rel_str)
        visitor.visit(tree)
        visitor.finalize_local_calls()

        functions = [module_ep] + visitor.functions

        parsed_files.append(
            ParsedFile(
                file_path=rel_str,
                imports=visitor.imports,
                functions=functions,
                calls=visitor.calls,
            )
        )

        # Collect entry points
        for fn in functions:
            if fn.is_entry_point:
                all_entry_points.append(fn.qualname)

    return ProjectASTResult(
        project_path=str(project_dir),
        files=parsed_files,
        entry_points=sorted(set(all_entry_points)),
    )
