# 🛡️ PyReach: Python Vulnerability Reachability Analyzer

[![PyReach CI & Reachability Guard](https://github.com/thesilentghost07/pyreach/actions/workflows/ci.yml/badge.svg)](https://github.com/thesilentghost07/pyreach/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-193%20passed-brightgreen.svg)](tests/)
[![Security](https://img.shields.io/badge/security-zero--code--execution-success.svg)](backend/)

> **Hacktoberfest 2026 — Hack Day Sonipat**  
> **Team:** CodeSins  
> **Problem Statement 03:** Python Vulnerability Reachability Analyzer

---

## 📌 Executive Summary

Traditional Software Composition Analysis (SCA) tools alert on any package listed in `requirements.txt` with a known CVE, regardless of whether that vulnerable functionality is ever executed. This creates alert fatigue, with up to **85% of vulnerability alerts representing uncalled, dormant code**.

**PyReach** deterministically inspects Python source code using Abstract Syntax Trees (`ast`) and Breadth-First Search (`BFS`) call-graph traversal to determine whether an application can reach vulnerable functions within its dependencies. It delivers three evidence-backed verdicts:

* 🔴 **`REACHABLE`**: A verifiable static call path exists from an application entry point to a vulnerable function sink. Complete with exact line numbers and intermediate call steps.
* 🟢 **`NOT_REACHABLE`**: The dependency is imported or installed, but static analysis proves no call path reaches vulnerable sinks, and zero dynamic hazards exist.
* 🟡 **`UNCERTAIN`**: Dynamic reflection (`getattr`, `eval`, `exec`), unpinned dependency versions, missing advisory symbol mappings, or parse errors prevent conclusive proof. Handled conservatively to prevent dangerous false negatives.

---

## 🏛️ Team Architecture & Division of Responsibility

PyReach was designed as a modular 4-member pipeline with locked Pydantic v2 data contracts (`backend/schemas.py`):

| Role & Owner | Primary Module | Key Responsibilities |
| :--- | :--- | :--- |
| **Member 1 (Pulkit Goel)**<br>AST & Project Scanner | [`backend/ast_scanner.py`](backend/ast_scanner.py) | Safely parses `.py` files as plain text with `ast.parse()`, tracks imports and local aliases (`from yaml import load as yl`), identifies function definitions, detects entry points (`main()`, `<module>`), and flags dynamic constructs (`getattr`, `eval`, `exec`). |
| **Member 2 (Vibhav Maurya)**<br>Reachability Engine | [`backend/reachability.py`](backend/reachability.py) | Constructs directed call graphs from AST nodes, traverses paths from entry points to vulnerable symbols using Breadth-First Search (BFS), constructs ordered `EvidenceStep` chains, and applies conservative uncertainty rules. |
| **Member 3 (Nischay Jain)**<br>Advisory Resolver & API | [`backend/deps_advisory.py`](backend/deps_advisory.py)<br>[`backend/main.py`](backend/main.py) | Parses `requirements.txt` manifests, queries the OSV REST API with 3-second timeouts and offline curated fallback (`backend/symbol_map.json`), and exposes FastAPI endpoints (`/api/health`, `/api/fixtures`, `/api/scan`). |
| **Member 4 (Uday Saha)**<br>Frontend & Platform | [`html/main.html`](html/main.html)<br>[`backend/cli.py`](backend/cli.py) | Builds the obsidian web dashboard, executive CLI reporter with PR Markdown output, synthetic test fixtures (`tests/fixtures/`), sample evaluation projects (`examples/`), and GitHub Actions CI workflow. |

---

## 🔒 Static Analysis Safety & Correctness Rules

1. **Zero Code Execution Guarantee**: PyReach **never** imports, executes, or runs `eval()` on scanned project code. All analysis is performed statically using standard library `ast.parse()` on UTF-8 source text.
2. **Conservative Uncertainty**: If an advisory lacks machine-readable function symbols, a dependency version is unpinned, or the code uses dynamic reflection (`getattr()`, `eval()`, `exec()`), PyReach will **never** claim `NOT_REACHABLE`. It conservatively returns `UNCERTAIN` with the exact file, line, and reason.
3. **Reproducible Evidence**: Every `REACHABLE` finding includes a machine-readable array of `EvidenceStep` items (`from_symbol -> to_symbol` at `file:line`) that security engineers and developers can independently verify.
4. **Offline Resilience**: If the OSV API is unreachable or rate-limited, PyReach falls back gracefully to `backend/symbol_map.json`, recording a clear warning without crashing.

---

## 🚀 Quick Start & Installation

### 1. Prerequisites & Environment Setup

```bash
# Clone the repository
git clone https://github.com/thesilentghost07/pyreach.git
cd pyreach

# Create and activate Python 3.11+ virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Running on Port 8000 (Backend API + Integrated Dashboard)

PyReach includes an integrated, zero-dependency obsidian security dashboard served directly by FastAPI on **port 8000**:

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

* **Dashboard URL:** [`http://127.0.0.1:8000/`](http://127.0.0.1:8000/) or [`http://127.0.0.1:8000/html/main.html`](http://127.0.0.1:8000/html/main.html)
* **Interactive API Docs:** [`http://127.0.0.1:8000/docs`](http://127.0.0.1:8000/docs)
* **Liveness Probe:** [`http://127.0.0.1:8000/api/health`](http://127.0.0.1:8000/api/health)

### 3. Running on Port 5173 (Frontend Development Server)

If you prefer to run the web interface through a separate frontend development server on **port 5173**:

```bash
# Option A: Standard Python HTTP server on port 5173
python3 -m http.server 5173

# Option B: Using Vite / Node (if Node.js is installed)
npx vite --port 5173
```

Open [`http://localhost:5173/`](http://localhost:5173/) or [`http://localhost:5173/index.html`](http://localhost:5173/index.html). The dashboard connects directly to the FastAPI backend running on port 8000.

### 4. Running via Command Line (CLI)

```bash
# Scan default evaluation fixtures and output executive Markdown
python -m backend.cli

# Scan a specific directory and output formatted JSON
python -m backend.cli examples/sample_project --format json

# Export a GitHub PR comment Markdown report
python -m backend.cli --output pyreach_report.md
```

### 5. Running Automated Tests

```bash
python -m pytest tests/ -v
```

* **Test Suite:** 193 unit and integration tests covering AST scanning, aliased imports, cyclic recursion, cross-file hops, dynamic reflection, OSV API fallbacks, FastAPI endpoints, and reachability traversal.

---

## 🧪 Demonstration & Acceptance Scenarios

PyReach includes deterministic evaluation fixtures under `tests/fixtures/` and a complete multi-finding project under `examples/sample_project/`:

### Scenario 1: Confirmed Reachable (`tests/fixtures/reachable_app/`)
* **Manifest:** `pyyaml==5.3.1` (affected by `PYSEC-2020-96` / `CVE-2020-14343`)
* **Code:** `app.run()` calls `yaml.load("payload: true")`
* **Verdict:** 🔴 **`REACHABLE`** (Confidence: `high`)
* **Evidence:** `app.run` (line 4) ➔ `yaml.load`

### Scenario 2: Suppressed / Not Reachable (`tests/fixtures/not_reachable_app/`)
* **Manifest:** `pyyaml==5.3.1`
* **Code:** `app.run()` calls `yaml.safe_load("payload: true")`
* **Verdict:** 🟢 **`NOT_REACHABLE`** (Confidence: `medium`)
* **Evidence:** No static call path exists to vulnerable symbol `yaml.load`; zero dynamic execution hazards detected.

### Scenario 3: Dynamic Hazard (`tests/fixtures/uncertain_app/`)
* **Manifest:** `pyyaml==5.3.1`
* **Code:** `loader = getattr(yaml, "load"); loader(...)`
* **Verdict:** 🟡 **`UNCERTAIN`** (Confidence: `low`)
* **Uncertainty Reason:** `Dynamic call hazard at app.py:4 (getattr)`

### Scenario 4: Multi-Finding Project (`examples/sample_project/`)
* **Manifest:** `pyyaml==5.3.1` and `requests==2.19.0`
* **Code:** Direct call to `yaml.load()` (line 12) + dynamic call `getattr(requests, ...)` (line 15).
* **Actual Output:** Generated and verified in [`examples/actual_scan_output.json`](examples/actual_scan_output.json).

---

## 📊 Decision Logic & Verdict Table

| Condition | Verdict | Confidence | Evidence & Remediation |
| :--- | :---: | :---: | :--- |
| Advisory matched + known vulnerable symbol + static call chain exists from entry point to symbol | **`REACHABLE`** | High | Full step-by-step `EvidenceStep` call chain showing caller, callee, file, and line number. |
| Advisory matched + known symbol + clean AST + zero dynamic call hazards + no call path found | **`NOT_REACHABLE`** | Medium | Verifiable proof of dormancy within analyzed scope. Alert suppressed. |
| Advisory matched, but advisory does not specify machine-readable function symbols in OSV or map | **`UNCERTAIN`** | Low | Cannot safely rule out reachability without known symbols. |
| Code uses dynamic reflection (`getattr`, `eval`, `exec`, `importlib`) along execution path | **`UNCERTAIN`** | Low | Exact file, line, and dynamic construct cited in `uncertainty_reasons`. |
| Dependency version in `requirements.txt` is unpinned (`>=`, `~=`) | **`UNCERTAIN`** | Low | Exact installed version cannot be verified statically. |
| Network error querying OSV and no offline curated match exists | **`UNCERTAIN`** | Low | Graceful fallback; warning recorded in report. |

---

## 🤖 AI Model Disclosure & Governance

In strict accordance with the Hacktoberfest 2026 guidelines:

* **Product Models Integrated in Application:** **`None`**  
  PyReach's core security engine is a 100% deterministic Python standard-library `ast` static analyzer and graph BFS pathfinder. No AI model is used to fabricate, infer, or override security verdicts.
* **AI Coding Assistants Used During Development:**  
  * **Google Gemini Pro & Google Antigravity:** Accelerated boilerplate code generation, recursive AST visitor scaffolding, unit test suites, and dashboard UI styling under human engineering review.
  * **Google Gemini Flash:** Fast specification reference, OSV query modeling, and FastAPI route structure.
  * **ChatGPT:** Early architecture planning and brainstorming.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
