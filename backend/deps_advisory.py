"""
deps_advisory.py — Member 3 (Nischay)

Parses a Python project's requirements.txt to extract dependencies,
then matches them against known vulnerability advisories using:
  1. The OSV API (online, with 3-second timeout)
  2. Our offline curated symbol_map.json (fallback / offline-only)

Returns a 3-tuple: (dependencies, advisories, warnings)

SAFETY: Never executes, imports, or runs any scanned project code.
         Reads files as plain text only.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional, Tuple

from backend.schemas import AdvisoryMatch, Dependency

# ---------------------------------------------------------------------------
# Package-name normalisation (PEP 503)
# ---------------------------------------------------------------------------

# This regex replaces any run of underscores, dots, or hyphens with a single
# hyphen, then lowercases. So "PyYAML" -> "pyyaml", "my_pkg.name" -> "my-pkg-name".
_NORMALISE_RE = re.compile(r"[-_.]+")


def _normalise_name(raw: str) -> str:
    """Normalise a package name to PEP 503 form (lowercase, hyphens)."""
    return _NORMALISE_RE.sub("-", raw).lower()


# ---------------------------------------------------------------------------
# Load the offline curated symbol map
# ---------------------------------------------------------------------------

# Path to the JSON file sitting next to this module
_SYMBOL_MAP_PATH = Path(__file__).resolve().parent / "symbol_map.json"


def _load_symbol_map() -> list[dict]:
    """Read symbol_map.json and return the 'entries' list.

    If the file is missing or malformed, returns an empty list
    (never crashes the scan).
    """
    try:
        text = _SYMBOL_MAP_PATH.read_text(encoding="utf-8", errors="replace")
        data = json.loads(text)
        return data.get("entries", [])
    except (OSError, json.JSONDecodeError):
        return []


def _match_symbol_map(
    name: str, version: Optional[str], entries: list[dict]
) -> list[dict]:
    """Find all symbol_map entries matching a normalised package name + exact version."""
    matches = []
    for entry in entries:
        if entry.get("package") != name:
            continue
        # Match if the exact version is in the entry's versions list
        versions_list = entry.get("versions", [])
        if version and version in versions_list:
            matches.append(entry)
    return matches


# ---------------------------------------------------------------------------
# Requirements.txt parser
# ---------------------------------------------------------------------------

# Regex to split a requirement line into package name and version specifier.
# Handles extras like pkg[extra1,extra2]==1.0.0 and environment markers after ;
# Group 1: package name (may include extras in brackets)
# Group 2: version operator + version string (optional)
_REQ_LINE_RE = re.compile(
    r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"  # package name
    r"(\[[^\]]*\])?"                                    # optional extras [...]
    r"\s*"
    r"(===|==|~=|!=|>=|<=|>|<)?"                        # optional operator
    r"\s*"
    r"([^\s,;#]*)?"                                     # optional version
)


def _parse_requirements(
    project_dir: Path,
) -> Tuple[List[Dependency], List[str]]:
    """Parse project_dir/requirements.txt into Dependency objects.

    Returns (dependencies, warnings). Never crashes.
    """
    warnings: list[str] = []
    deps: list[Dependency] = []

    req_path = project_dir / "requirements.txt"

    # --- Handle missing requirements.txt ---
    if not req_path.is_file():
        warnings.append(
            f"No requirements.txt found in {project_dir}; dependency analysis skipped"
        )
        # Check if pyproject.toml exists (optional parsing not implemented)
        if (project_dir / "pyproject.toml").is_file():
            warnings.append(
                f"pyproject.toml found in {project_dir} but pyproject.toml "
                f"parsing is not supported; only requirements.txt is analyzed"
            )
        return deps, warnings

    # --- Read the file as plain text (NEVER execute it) ---
    try:
        text = req_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        warnings.append(f"Could not read requirements.txt: {exc}")
        return deps, warnings

    lines = text.splitlines()

    for line_no_0, raw_line in enumerate(lines):
        line_no = line_no_0 + 1  # 1-based

        # Strip inline comments: everything after the first '#'
        line = raw_line.split("#", 1)[0].strip()

        # Skip blank lines
        if not line:
            continue

        # --- Handle option/flag lines starting with '-' ---
        if line.startswith("-"):
            if line.startswith("-r") or line.startswith("--requirement"):
                warnings.append(
                    f"Line {line_no}: '-r' requirement file includes are not "
                    f"followed ({raw_line.strip()})"
                )
            elif line.startswith("-e") or line.startswith("--editable"):
                warnings.append(
                    f"Line {line_no}: editable/VCS installs are unsupported "
                    f"({raw_line.strip()})"
                )
            # Other flags like --index-url are silently ignored
            continue

        # --- Handle URL / VCS lines ---
        if any(line.startswith(prefix) for prefix in ("http://", "https://", "git+")):
            deps.append(Dependency(
                name=line.strip(),
                version=None,
                is_pinned=False,
                source_file="requirements.txt",
                line=line_no,
            ))
            warnings.append(
                f"Line {line_no}: URL/VCS dependency cannot be version-pinned "
                f"statically ({raw_line.strip()})"
            )
            continue

        # --- Strip environment markers after ';' ---
        line = line.split(";", 1)[0].strip()

        # --- Handle @ URL specifiers (PEP 440 direct references) ---
        if "@" in line and ("http://" in line or "https://" in line):
            # e.g. "package @ https://..."
            pkg_part = line.split("@", 1)[0].strip()
            norm_name = _normalise_name(pkg_part) if pkg_part else line.strip()
            deps.append(Dependency(
                name=norm_name,
                version=None,
                is_pinned=False,
                source_file="requirements.txt",
                line=line_no,
            ))
            warnings.append(
                f"Line {line_no}: URL/VCS dependency cannot be version-pinned "
                f"statically ({raw_line.strip()})"
            )
            continue

        # --- Check for comma-separated constraints (e.g. >=1.0,<2.0) ---
        if "," in line:
            # Try to extract just the package name
            m = _REQ_LINE_RE.match(line)
            if m:
                pkg_name = _normalise_name(m.group(1))
                deps.append(Dependency(
                    name=pkg_name,
                    version=None,
                    is_pinned=False,
                    source_file="requirements.txt",
                    line=line_no,
                ))
            else:
                warnings.append(
                    f"Line {line_no}: could not parse requirement ({raw_line.strip()})"
                )
            continue

        # --- Standard single-constraint line ---
        m = _REQ_LINE_RE.match(line)
        if not m:
            warnings.append(
                f"Line {line_no}: could not parse requirement ({raw_line.strip()})"
            )
            continue

        pkg_raw = m.group(1)
        operator = m.group(4)  # may be None (bare name)
        version_str = m.group(5) if m.group(5) else None

        pkg_name = _normalise_name(pkg_raw)

        # Determine if pinned: only == or === with a concrete version, no wildcard
        is_pinned = False
        version: Optional[str] = None

        if operator in ("==", "===") and version_str and "*" not in version_str:
            is_pinned = True
            version = version_str
        elif operator and version_str:
            # Unpinned with a specifier (>=, ~=, !=, >, <, <=)
            is_pinned = False
            version = None

        deps.append(Dependency(
            name=pkg_name,
            version=version,
            is_pinned=is_pinned,
            source_file="requirements.txt",
            line=line_no,
        ))

    return deps, warnings


# ---------------------------------------------------------------------------
# OSV API helper (isolated for easy mocking in tests)
# ---------------------------------------------------------------------------

def _query_osv_api(package: str, version: str, timeout: float = 3.0) -> dict:
    """POST to OSV and return the parsed JSON response.

    Raises on network/timeout/parse errors — the caller handles fallback.
    """
    url = "https://api.osv.dev/v1/query"
    payload = json.dumps({
        "package": {"name": package, "ecosystem": "PyPI"},
        "version": version,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# Extract vulnerable symbols from an OSV vulnerability object
# ---------------------------------------------------------------------------

def _extract_osv_symbols(vuln: dict) -> Tuple[List[str], str]:
    """Pull vulnerable function symbols from OSV ecosystem_specific.imports.

    Returns (symbols_list, symbol_source).
    symbol_source is "osv_imports" if symbols found, otherwise "none".
    """
    symbols: list[str] = []
    seen: set[str] = set()

    for affected_block in vuln.get("affected", []):
        eco = affected_block.get("ecosystem_specific", {})
        imports_list = eco.get("imports", [])
        for imp in imports_list:
            module_path = imp.get("path", "")
            for sym in imp.get("symbols", []):
                qualified = f"{module_path}.{sym}" if module_path else sym
                if qualified not in seen:
                    seen.add(qualified)
                    symbols.append(qualified)

    if symbols:
        return symbols, "osv_imports"
    return [], "none"


def _extract_affected_versions(vuln: dict) -> str:
    """Build a concise affected-versions string from OSV data."""
    parts: list[str] = []
    for aff in vuln.get("affected", []):
        for rng in aff.get("ranges", []):
            events = rng.get("events", [])
            intro = next((e.get("introduced") for e in events if "introduced" in e), None)
            fixed = next((e.get("fixed") for e in events if "fixed" in e), None)
            if intro and fixed:
                parts.append(f">={intro},<{fixed}")
            elif intro:
                parts.append(f">={intro}")
        # Also check explicit versions list
        for v in aff.get("versions", []):
            if v not in parts:
                parts.append(v)
    return ", ".join(parts) if parts else "unknown"


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------

def resolve_dependencies_and_advisories(
    project_dir: Path,
    use_network: bool = True,
) -> Tuple[List[Dependency], List[AdvisoryMatch], List[str]]:
    """Parse dependencies and match advisories.

    Returns (dependencies, advisories, warnings).

    When use_network=True and a dependency is pinned, queries the OSV API
    (3-second timeout). On failure, falls back to symbol_map.json.

    When use_network=False, uses symbol_map.json only (no HTTP calls).
    """
    # 1. Parse requirements.txt
    deps, warnings = _parse_requirements(project_dir)

    # 2. Load offline curated map
    sm_entries = _load_symbol_map()

    # 3. Track network-disabled warning (emit once)
    if not use_network:
        warnings.append(
            "Network disabled: advisory data limited to curated symbol_map.json"
        )

    # 4. For each dependency, resolve advisories
    advisories: list[AdvisoryMatch] = []
    seen_advisory_keys: set[tuple[str, str]] = set()  # (package, advisory_id)

    for dep in deps:
        # -- Warn about unpinned deps --
        if not dep.is_pinned:
            warnings.append(
                f"Dependency '{dep.name}' is unpinned; exact affected state "
                f"cannot be verified statically"
            )
            continue  # Do not query OSV with a guessed version

        assert dep.version is not None  # pinned always has a version

        osv_vulns: list[dict] = []
        osv_queried = False

        # -- Online path --
        if use_network:
            try:
                result = _query_osv_api(dep.name, dep.version)
                osv_vulns = result.get("vulns", [])
                osv_queried = True

                # Warn about pagination
                if result.get("next_page_token"):
                    warnings.append(
                        f"OSV response for {dep.name}=={dep.version} was "
                        f"paginated (next_page_token present); additional "
                        f"advisories may exist"
                    )

            except (
                urllib.error.URLError,
                urllib.error.HTTPError,
                TimeoutError,
                OSError,
                json.JSONDecodeError,
                KeyError,
                TypeError,
                ValueError,
            ) as exc:
                warnings.append(
                    f"OSV lookup failed for {dep.name}=={dep.version}: "
                    f"{exc}; using offline curated map only"
                )

        # -- Process OSV results --
        for vuln in osv_vulns:
            adv_id = vuln.get("id")
            if not adv_id:
                warnings.append(
                    f"Skipped malformed OSV entry for {dep.name} (missing 'id')"
                )
                continue

            dedup_key = (dep.name, adv_id)
            if dedup_key in seen_advisory_keys:
                continue
            seen_advisory_keys.add(dedup_key)

            # Summary
            summary = vuln.get("summary", "")
            if not summary:
                details = vuln.get("details", "No summary provided")
                summary = details[:200]

            # Affected versions string
            affected_versions = _extract_affected_versions(vuln)

            # Extract symbols from OSV
            symbols, symbol_source = _extract_osv_symbols(vuln)

            # If OSV didn't provide symbols, try offline map enrichment
            if not symbols:
                offline_matches = _match_symbol_map(dep.name, dep.version, sm_entries)
                for om in offline_matches:
                    om_id = om.get("advisory_id", "")
                    om_aliases = om.get("aliases", [])
                    vuln_aliases = vuln.get("aliases", [])
                    # Match by advisory_id or overlapping aliases
                    if (
                        om_id == adv_id
                        or set(om_aliases) & set(vuln_aliases)
                        or om_id in vuln_aliases
                        or adv_id in om_aliases
                    ):
                        om_syms = om.get("vulnerable_symbols", [])
                        if om_syms:
                            symbols = om_syms
                            symbol_source = "curated_map"
                            break

            advisories.append(AdvisoryMatch(
                package=dep.name,
                installed_version=dep.version,
                advisory_id=adv_id,
                summary=summary,
                affected_versions=affected_versions,
                vulnerable_symbols=symbols,
                symbol_source=symbol_source,
            ))

        # -- Offline-only path (also catches OSV failures with no results) --
        # Check symbol_map for entries not already found via OSV
        offline_matches = _match_symbol_map(dep.name, dep.version, sm_entries)
        for om in offline_matches:
            om_id = om.get("advisory_id", "")
            dedup_key = (dep.name, om_id)
            if dedup_key in seen_advisory_keys:
                continue
            seen_advisory_keys.add(dedup_key)

            advisories.append(AdvisoryMatch(
                package=dep.name,
                installed_version=dep.version,
                advisory_id=om_id,
                summary=om.get("summary", ""),
                affected_versions=om.get("affected_range", "unknown"),
                vulnerable_symbols=om.get("vulnerable_symbols", []),
                symbol_source="curated_map" if om.get("vulnerable_symbols") else "none",
            ))

    return deps, advisories, warnings
