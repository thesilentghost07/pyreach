# Synthetic Evaluation Test Fixtures

These fixtures are deterministic synthetic test projects designed to evaluate the PyReach static analysis and call-graph reachability engine:

1. `reachable_app/`: Synthetic fixture with a confirmed static call path from `app.run` to `yaml.load`. Expected verdict: `REACHABLE` (confidence: `high`).
2. `not_reachable_app/`: Synthetic fixture importing PyYAML but calling only safe function `yaml.safe_load`. Expected verdict: `NOT_REACHABLE` (confidence: `medium`).
3. `uncertain_app/`: Synthetic fixture using dynamic reflection `getattr(yaml, "load")`. Expected verdict: `UNCERTAIN` (confidence: `low`).
4. `edge_cases/`: 6 focused edge-case scenarios covering aliased imports, cross-file hops, cyclic recursion, dynamic eval reflection, nested closures, and uncalled sinks.

None of these fixtures represent production application code. All advisories mapped to `demo-*` are labeled `SYNTHETIC-DEMO-*`.
