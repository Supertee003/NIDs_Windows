# Clean Runner Reassessment

The Host output still contains overlapping group sections and multiple final counters. Direct inspection of the latest log shows `GROUP 3` immediately invoking signed-policy tests, then a final counter, then `Nose Python tests`, then Groups 4–8. The same log later reports the signed-policy, Cython, detection, rules, and TypeScript policy tests passing. These are runner-flow artifacts, not source failures.

The batch implementation has been replaced by `scripts/run_eight_groups_safe.py`. The `.cmd` file is now a minimal wrapper. The Python orchestrator uses:

- `subprocess.run(..., cwd=...)` for every command;
- an exclusive lock file created with `open(..., "x")`;
- one unique output directory per process;
- one sequential process in the documented Group 1–8 order;
- captured stdout/stderr written to one log;
- explicit `prevention_gate=closed` and no WFP mutation commands.

The latest direct source evidence is positive: Zig runtime, WFP observe-only, FIM observe-only, host telemetry, Rust PEP, Shield, Cython, detection, policy, and TypeScript tests all show passing output in the non-overlapped portions. The next result must come from the Python orchestrator and must contain exactly eight group headers and one final `PASS=... FAIL=... SKIP=...` line.
