"""
tests/test_ast_scanner.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Comprehensive unit tests for ``backend.ast_scanner.scan_project_ast``.

Every test writes self-contained Python source files into a ``tmp_path``
fixture directory and asserts exact structural properties of the resulting
``ProjectASTResult``.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from backend.ast_scanner import scan_project_ast


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(tmp: Path, rel: str, code: str) -> Path:
    """Write *code* to ``tmp / rel``, creating intermediate dirs."""
    p = tmp / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(code), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# 1. Direct & aliased imports
# ---------------------------------------------------------------------------


class TestDirectAndAliasedImports:
    """Verify that ``import yaml as y`` (``y.load``) and
    ``from urllib3 import PoolManager as PM`` (``PM()``) resolve correctly
    with exact line numbers."""

    @pytest.fixture()
    def result(self, tmp_path: Path):
        _write(
            tmp_path,
            "main.py",
            """\
            import yaml as y
            from urllib3 import PoolManager as PM

            data = y.load(open("f"))
            pool = PM()
            """,
        )
        return scan_project_ast(tmp_path)

    def test_yaml_load_resolved(self, result):
        calls = result.files[0].calls
        yaml_calls = [c for c in calls if c.raw_callee == "y.load"]
        assert len(yaml_calls) == 1
        assert yaml_calls[0].resolved_callee == "yaml.load"
        assert yaml_calls[0].line == 4

    def test_poolmanager_resolved(self, result):
        calls = result.files[0].calls
        pm_calls = [c for c in calls if c.raw_callee == "PM"]
        assert len(pm_calls) == 1
        assert pm_calls[0].resolved_callee == "urllib3.PoolManager"
        assert pm_calls[0].line == 5

    def test_import_records(self, result):
        imports = result.files[0].imports
        aliases = {ir.alias: ir for ir in imports}
        assert "y" in aliases
        assert aliases["y"].module == "yaml"
        assert aliases["y"].line == 1
        assert "PM" in aliases
        assert aliases["PM"].module == "urllib3"
        assert aliases["PM"].imported_name == "PoolManager"
        assert aliases["PM"].line == 2


# ---------------------------------------------------------------------------
# 2. Intra-file calls & entry points
# ---------------------------------------------------------------------------


class TestIntraFileCallsAndEntrypoints:
    """Verify ``<module>``, ``main()``, and ``@app.post`` async function are
    entry points, and local helper calls resolve within the module."""

    @pytest.fixture()
    def result(self, tmp_path: Path):
        _write(
            tmp_path,
            "server.py",
            """\
            from fastapi import FastAPI

            app = FastAPI()

            def helper(x):
                return x + 1

            def main():
                helper(42)

            @app.post("/scan")
            async def scan_endpoint(payload):
                return helper(payload)
            """,
        )
        return scan_project_ast(tmp_path)

    def test_module_entry_point(self, result):
        fns = result.files[0].functions
        mod = [f for f in fns if f.name == "<module>"]
        assert len(mod) == 1
        assert mod[0].is_entry_point is True
        assert mod[0].qualname == "server.<module>"

    def test_main_entry_point(self, result):
        fns = result.files[0].functions
        mains = [f for f in fns if f.name == "main"]
        assert len(mains) == 1
        assert mains[0].is_entry_point is True

    def test_decorated_async_entry_point(self, result):
        fns = result.files[0].functions
        eps = [f for f in fns if f.name == "scan_endpoint"]
        assert len(eps) == 1
        assert eps[0].is_entry_point is True

    def test_helper_not_entry(self, result):
        fns = result.files[0].functions
        helpers = [f for f in fns if f.name == "helper"]
        assert len(helpers) == 1
        assert helpers[0].is_entry_point is False

    def test_local_helper_call_resolved(self, result):
        calls = result.files[0].calls
        helper_calls = [c for c in calls if c.raw_callee == "helper"]
        assert len(helper_calls) == 2
        for hc in helper_calls:
            assert hc.resolved_callee == "server.helper"

    def test_entry_points_list(self, result):
        assert "server.<module>" in result.entry_points
        assert "server.main" in result.entry_points
        assert "server.scan_endpoint" in result.entry_points


# ---------------------------------------------------------------------------
# 3. Class method self-resolution
# ---------------------------------------------------------------------------


class TestClassMethodSelfResolution:
    """Verify ``self.parse()`` inside ``ConfigLoader`` in ``app/loader.py``
    resolves to ``app.loader.ConfigLoader.parse``."""

    @pytest.fixture()
    def result(self, tmp_path: Path):
        _write(tmp_path, "app/__init__.py", "")
        _write(
            tmp_path,
            "app/loader.py",
            """\
            class ConfigLoader:
                def parse(self, data):
                    return data

                def run(self, raw):
                    return self.parse(raw)
            """,
        )
        return scan_project_ast(tmp_path)

    def test_self_call_resolved(self, result):
        loader_file = [f for f in result.files if f.file_path.endswith("loader.py")][0]
        self_calls = [c for c in loader_file.calls if c.raw_callee == "self.parse"]
        assert len(self_calls) == 1
        assert self_calls[0].resolved_callee == "app.loader.ConfigLoader.parse"

    def test_method_qualnames(self, result):
        loader_file = [f for f in result.files if f.file_path.endswith("loader.py")][0]
        qnames = {f.qualname for f in loader_file.functions if f.name != "<module>"}
        assert "app.loader.ConfigLoader.parse" in qnames
        assert "app.loader.ConfigLoader.run" in qnames


# ---------------------------------------------------------------------------
# 4. Nested calls extracted
# ---------------------------------------------------------------------------


class TestNestedCallsExtracted:
    """Verify ``print(sanitize(yaml.load(raw)))`` captures all three call
    sites."""

    @pytest.fixture()
    def result(self, tmp_path: Path):
        _write(
            tmp_path,
            "pipe.py",
            """\
            import yaml

            def sanitize(x):
                return x

            print(sanitize(yaml.load("raw")))
            """,
        )
        return scan_project_ast(tmp_path)

    def test_all_three_calls_captured(self, result):
        calls = result.files[0].calls
        raw_callees = {c.raw_callee for c in calls}
        assert "print" in raw_callees
        assert "sanitize" in raw_callees
        assert "yaml.load" in raw_callees

    def test_yaml_load_resolved(self, result):
        calls = result.files[0].calls
        yl = [c for c in calls if c.raw_callee == "yaml.load"]
        assert len(yl) == 1
        assert yl[0].resolved_callee == "yaml.load"

    def test_all_on_same_line(self, result):
        calls = result.files[0].calls
        line6_calls = [c for c in calls if c.line == 6]
        assert len(line6_calls) == 3


# ---------------------------------------------------------------------------
# 5. Dynamic call & wildcard detection
# ---------------------------------------------------------------------------


class TestDynamicCallAndWildcardDetection:
    """Verify ``getattr(yaml, fn)()``, ``eval("x")``, ``handlers[k]()``,
    and ``from yaml import *`` all produce ``is_dynamic=True`` with clear
    ``dynamic_reason`` strings."""

    @pytest.fixture()
    def result(self, tmp_path: Path):
        _write(
            tmp_path,
            "dyn.py",
            """\
            import yaml
            from yaml import *

            fn = "load"
            getattr(yaml, fn)()
            eval("x")
            handlers = {}
            handlers["k"]()
            """,
        )
        return scan_project_ast(tmp_path)

    def test_wildcard_dynamic(self, result):
        calls = result.files[0].calls
        wildcards = [c for c in calls if "Wildcard import" in (c.dynamic_reason or "")]
        assert len(wildcards) == 1
        assert wildcards[0].is_dynamic is True
        assert "from yaml import *" in wildcards[0].dynamic_reason

    def test_getattr_dynamic(self, result):
        calls = result.files[0].calls
        ga = [c for c in calls if c.raw_callee == "getattr"]
        assert len(ga) == 1
        assert ga[0].is_dynamic is True
        assert "Dynamic reflection/execution call" in ga[0].dynamic_reason

    def test_eval_dynamic(self, result):
        calls = result.files[0].calls
        ev = [c for c in calls if c.raw_callee == "eval"]
        assert len(ev) == 1
        assert ev[0].is_dynamic is True

    def test_subscript_call_dynamic(self, result):
        calls = result.files[0].calls
        expr = [c for c in calls if c.raw_callee == "<expr>"]
        # Two <expr> calls: getattr(yaml, fn)() -> the outer call is <expr>,
        # and handlers["k"]() is also <expr>.
        assert len(expr) >= 1
        for e in expr:
            assert e.is_dynamic is True
            assert "Dynamic/computed call expression" in e.dynamic_reason


# ---------------------------------------------------------------------------
# 6. Malformed Python file handled gracefully
# ---------------------------------------------------------------------------


class TestMalformedPythonFileHandledGracefully:
    """Verify a file with ``SyntaxError`` populates ``ParsedFile.parse_error``
    without crashing the scan of valid sibling files."""

    @pytest.fixture()
    def result(self, tmp_path: Path):
        _write(
            tmp_path,
            "good.py",
            """\
            def greet():
                print("hello")
            """,
        )
        _write(
            tmp_path,
            "bad.py",
            """\
            def broken(
                # missing closing paren & colon
            """,
        )
        return scan_project_ast(tmp_path)

    def test_bad_file_has_parse_error(self, result):
        bad = [f for f in result.files if "bad" in f.file_path]
        assert len(bad) == 1
        assert bad[0].parse_error is not None
        assert len(bad[0].parse_error) > 0

    def test_good_file_parsed_ok(self, result):
        good = [f for f in result.files if "good" in f.file_path]
        assert len(good) == 1
        assert good[0].parse_error is None
        fnames = {fn.name for fn in good[0].functions}
        assert "greet" in fnames
        assert "<module>" in fnames

    def test_both_files_present(self, result):
        assert len(result.files) == 2

    def test_entry_points_from_good_file(self, result):
        assert "good.<module>" in result.entry_points
