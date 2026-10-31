<!-- 
  PYREACH PULL REQUEST TEMPLATE
  Please complete all mandatory sections before requesting review.
-->

## 1. Summary of Changes
<!-- Provide a concise bulleted list of what this PR introduces, fixes, or refactors. -->
- 

## 2. File Ownership & Boundary Compliance
<!-- Verify that this PR modifies ONLY files assigned to your role. -->
- [ ] Modified only assigned files within designated scope.
- [ ] No direct commits to `main`; branched off clean `main`.

**Files Changed in this PR:**
- `path/to/file`

## 3. Mandatory AI Model Disclosure (Slide 14 Governance Requirement)
<!-- 
  Required for all submissions to secure 10 governance points per Slide 14.
  Do not delete or leave this section empty.
-->
| Category | Tool / Model Used | Purpose / Context |
| :--- | :--- | :--- |
| **Product Models (Integrated in Application)** | None | Pure deterministic Python AST + BFS static analysis |
| **AI Coding Assistants Used** | Google Gemini Pro, Google Antigravity | Code generation, test scaffolding, CI configuration |

## 4. Testing & Verification Checklist
<!-- All checks must pass before merging. -->
- [ ] Executed `python -m pytest tests/ -v` locally.
- [ ] All test items pass green (zero failed, zero errored).
- [ ] (If applicable) CLI verified: `python -m backend.cli --offline` executes cleanly.
- [ ] (If applicable) API endpoints verified via FastAPI test client.

**Test Run Output / Verification Proof:**
```text
# Paste pytest summary line here (e.g., 83 passed in 0.23s)
```

## 5. Breaking Changes & Integration Impact
- [ ] No breaking changes: Backward compatible with existing schemas and endpoints.
- [ ] Breaking change: Describe the migration path or impact on teammate modules below.
