#!/usr/bin/env python3
"""AEGIS doc checker - P3 Phase W: docs vs code verification.

Phase W exit condition:
  Documentation claims are machine-verified against the code:
    1. Required docs exist.
    2. aegisctl commands referenced in markdown CODE FENCES exist in
       scripts/aegisctl.py (top-level argparse subcommands).
       Commands used in prose are NOT checked (avoids false positives).
    3. AEGIS_* env vars documented in docs/ENV_VARS.md appear somewhere
       in code (core/*.zig, scripts/*.py, *.bat) - WARN only.
    4. shared/runtime/components.json parses as JSON - WARN if missing
       (deploy G56 first) but FAIL if present yet invalid.

Exit codes:
  0 = no FAIL items, 1 = at least one FAIL item.

Modes:
  python scripts/doc_checker.py             # check the repo (cwd)
  python scripts/doc_checker.py --root PATH # check another checkout
  python scripts/doc_checker.py --self-test # verify the checker itself

Pure stdlib. ASCII only. Deterministic output ordering.
"""

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------

REQUIRED_DOCS = [
    "docs/ARCHITECTURE.md",
    "docs/DEPLOYMENT.md",
    "docs/STRUCTURE.md",
    "docs/ENV_VARS.md",
    "docs/platform/p2-windows-platform.md",
    "docs/ai-context/governance.md",
]

AEGISCTL_RELPATH = "scripts/aegisctl.py"
COMPONENTS_RELPATH = "shared/runtime/components.json"
ENV_DOCS_RELPATH = "docs/ENV_VARS.md"

# Code locations scanned for env var usage.
ENV_SEARCH_GLOBS = ["core/*.zig", "scripts/*.py", "*.bat", "*.ps1"]

FENCE_RE = re.compile(r"```")
AEGISCTL_USE_RE = re.compile(
    r"(?:python\s+)?(?:scripts[/\\])?aegisctl(?:\.py)?\s+([a-z_0-9]+)"
)
ENV_VAR_RE = re.compile(r"\bAEGIS_[A-Z0-9_]+\b")

# ---------------------------------------------------------------
# Report
# ---------------------------------------------------------------


class Report(object):
    """Ordered collection of check results."""

    def __init__(self):
        self.items = []  # list of (level, code, message)

    def fail(self, code, message):
        self.items.append(("FAIL", code, message))

    def warn(self, code, message):
        self.items.append(("WARN", code, message))

    def ok(self, code, message):
        self.items.append(("OK", code, message))

    @property
    def fail_count(self):
        return sum(1 for item in self.items if item[0] == "FAIL")

    @property
    def warn_count(self):
        return sum(1 for item in self.items if item[0] == "WARN")

    def summary(self):
        lines = []
        for level, code, message in self.items:
            lines.append("  [%s] %s: %s" % (level, code, message))
        lines.append(
            "Summary: %d FAIL, %d WARN, %d total"
            % (self.fail_count, self.warn_count, len(self.items))
        )
        return "\n".join(lines)


# ---------------------------------------------------------------
# Check primitives (kept pure for the self-test)
# ---------------------------------------------------------------


def parse_aegisctl_commands(aegisctl_text):
    """Extract top-level argparse subcommand names from aegisctl.py.

    Matches 'sub.add_parser("name"' where 'sub' is the main subparser
    action. A negative lookbehind excludes nested actions such as
    'rules_sub.add_parser(...)'.
    """
    return set(
        re.findall(r'(?<![\w])sub\.add_parser\(\s*"([a-z_0-9]+)"', aegisctl_text)
    )


def extract_fence_aegisctl_uses(md_text):
    """Return aegisctl first-commands used inside markdown code fences."""
    commands = []
    in_fence = False
    for line in md_text.splitlines():
        if FENCE_RE.search(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            continue
        for match in AEGISCTL_USE_RE.finditer(line):
            commands.append(match.group(1))
    return commands


def check_required_docs(root, report):
    for relpath in REQUIRED_DOCS:
        if (root / relpath).is_file():
            report.ok("doc-exists", relpath)
        else:
            report.fail("doc-missing", relpath)


def check_aegisctl_commands(root, report):
    aegisctl_path = root / AEGISCTL_RELPATH
    if not aegisctl_path.is_file():
        report.fail("aegisctl-missing", AEGISCTL_RELPATH)
        return
    commands = parse_aegisctl_commands(
        aegisctl_path.read_text(encoding="utf-8", errors="replace")
    )
    if not commands:
        report.fail("aegisctl-unparseable", "no sub.add_parser() entries found")
        return
    report.ok("aegisctl-parsed", "%d top-level commands" % len(commands))

    docs_dir = root / "docs"
    if not docs_dir.is_dir():
        report.warn("docs-dir-missing", "docs/ not found; command usage unchecked")
        return

    documented = set()
    for md_path in sorted(docs_dir.rglob("*.md")):
        text = md_path.read_text(encoding="utf-8", errors="replace")
        for command in extract_fence_aegisctl_uses(text):
            documented.add(command)
            if command not in commands:
                rel = md_path.relative_to(root)
                report.fail(
                    "doc-cmd-unknown",
                    "%s uses 'aegisctl %s' but aegisctl.py has no such command"
                    % (rel, command),
                )
    undocumented = commands - documented
    for command in sorted(undocumented):
        report.warn("cmd-not-documented", "aegisctl %s" % command)


def check_env_vars(root, report):
    env_docs = root / ENV_DOCS_RELPATH
    if not env_docs.is_file():
        report.warn("env-docs-missing", ENV_DOCS_RELPATH)
        return
    text = env_docs.read_text(encoding="utf-8", errors="replace")
    documented_vars = sorted(set(ENV_VAR_RE.findall(text)))
    if not documented_vars:
        report.warn("env-vars-empty", "no AEGIS_* variables found in ENV_VARS.md")
        return

    code_chunks = []
    for pattern in ENV_SEARCH_GLOBS:
        for code_path in sorted(root.glob(pattern)):
            try:
                code_chunks.append(code_path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
    haystack = "\n".join(code_chunks)
    for var in documented_vars:
        if var in haystack:
            report.ok("env-var-used", var)
        else:
            report.warn("env-var-not-in-code", var)


def check_components_registry(root, report):
    components_path = root / COMPONENTS_RELPATH
    if not components_path.is_file():
        report.warn("components-missing", "%s (deploy G56 first)" % COMPONENTS_RELPATH)
        return
    try:
        data = json.loads(components_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        report.fail("components-invalid-json", str(exc))
        return
    if isinstance(data, dict):
        count = len(data)
    elif isinstance(data, list):
        count = len(data)
    else:
        report.fail("components-invalid-shape", "expected dict or list")
        return
    report.ok("components-parsed", "%d entries" % count)


# ---------------------------------------------------------------
# Runner
# ---------------------------------------------------------------


def run_checks(root):
    report = Report()
    check_required_docs(root, report)
    check_aegisctl_commands(root, report)
    check_env_vars(root, report)
    check_components_registry(root, report)
    return report


# ---------------------------------------------------------------
# Self-test (fixture based, no repo needed)
# ---------------------------------------------------------------

GOOD_AEGISCTL = (
    "def main():\n"
    "    sub = parser.add_subparsers()\n"
    '    sub.add_parser("status", help="status")\n'
    '    sub.add_parser("health", help="health")\n'
)

BAD_DOC = "# Doc\n\n```powershell\npython scripts/aegisctl.py bogus_cmd\n```\n"
GOOD_DOC = "# Doc\n\n```powershell\npython scripts/aegisctl.py status\n```\n"


def build_fixture(root, bad):
    """Create a small synthetic repo used by --self-test."""
    (root / "docs" / "platform").mkdir(parents=True)
    (root / "docs" / "ai-context").mkdir(parents=True)
    (root / "scripts").mkdir(parents=True)
    (root / "core").mkdir(parents=True)
    (root / "shared" / "runtime").mkdir(parents=True)
    (root / AEGISCTL_RELPATH).write_text(GOOD_AEGISCTL, encoding="utf-8")
    for relpath in REQUIRED_DOCS:
        if "ENV_VARS" in relpath:
            content = "# Env\n\n- AEGIS_TEST_VAR: test flag\n"
        else:
            content = "# %s\n" % relpath
        (root / relpath).write_text(content, encoding="utf-8")
    (root / "core" / "dummy.zig").write_text(
        "const std = @import(\"std\");\npub const X = AEGIS_TEST_VAR;\n",
        encoding="utf-8",
    )
    (root / COMPONENTS_RELPATH).write_text('{"aegis-nids": {}}', encoding="utf-8")
    # Env var check scans *.bat too; add a bat that sets the var.
    (root / "run_aegis.bat").write_text("set AEGIS_TEST_VAR=1\n", encoding="utf-8")
    doc_name = "docs/USAGE.md"
    (root / doc_name).write_text(BAD_DOC if bad else GOOD_DOC, encoding="utf-8")


def self_test():
    """Verify the checker catches a bad doc and passes a good repo."""
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        good_root = Path(tmp) / "good"
        build_fixture(good_root, bad=False)
        good_report = run_checks(good_root)
        results.append(("good repo has no FAIL", good_report.fail_count == 0))
        if good_report.fail_count:
            print(good_report.summary())
    with tempfile.TemporaryDirectory() as tmp:
        bad_root = Path(tmp) / "bad"
        build_fixture(bad_root, bad=True)
        bad_report = run_checks(bad_root)
        codes = set((item[1], item[2]) for item in bad_report.items if item[0] == "FAIL")
        caught = any("bogus_cmd" in message for _, message in codes)
        results.append(("bad repo FAIL caught (bogus_cmd)", caught))
    print("=== doc_checker self-test ===")
    all_ok = True
    for name, passed in results:
        print("  [%s] %s" % ("PASS" if passed else "FAIL", name))
        all_ok = all_ok and passed
    if all_ok:
        print("Self-test: ALL PASS")
        return 0
    print("Self-test: FAILED")
    return 1


# ---------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------


def main(argv=None):
    parser = argparse.ArgumentParser(description="AEGIS docs-vs-code checker (P3 Phase W)")
    parser.add_argument("--root", default=".", help="repo root to check (default: cwd)")
    parser.add_argument("--self-test", action="store_true", help="run the built-in self-test")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = Path(args.root).resolve()
    if not root.is_dir():
        print("Root not found: %s" % root, file=sys.stderr)
        return 1
    print("=== AEGIS doc checker (Phase W) ===")
    print("Root: %s" % root)
    report = run_checks(root)
    print(report.summary())
    return 1 if report.fail_count else 0


if __name__ == "__main__":
    sys.exit(main())
