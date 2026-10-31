# Hacktoberfest 2026 – Hack Day Sonipat

## Team Information
- Team Name: CodeSins
- Team Members:
  - Pulkit Goel (Team Leader)
  - Vibhav Maurya
  - Nischay Jain
  - Uday Saha

## Selected Problem Statement
- Problem 03: Python Vulnerability Reachability Analyzer

## AI Models Used & Justification
- Selected Model: `gemma4:e4b` / `gemma4:e2b` (Open-weight model running locally via Ollama)
- Reason for Selection: Python vulnerability advisories in the PyPA and OSV databases frequently describe affected functionality in unstructured English prose or raw patch diffs without explicitly listing machine-readable vulnerable function symbols under `ecosystem_specific`. We use Gemma 4 locally to parse unstructured CVE descriptions and patch headers to extract exact target function sinks (`module.function_name`), feeding those targets into our deterministic Python AST call-graph and BFS reachability verifier.
