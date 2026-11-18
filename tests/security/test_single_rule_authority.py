"""RULE-AUTHORITY-001: configs/Rules.json is the only rule authority.

A stale `config/Rules.json` mirror differed from the canonical file in two
`regex_pattern` values and was still loaded by the control API fallback, the
rule-mutation helpers and the golden-path evidence collector. A caller could
therefore validate one rule set, act on another, and publish evidence that
hashed the mirror while claiming the canonical path.

Contract pinned here:
  AC1. The legacy mirror is byte-identical to the canonical file.
  AC2. No rule-loading path reads the mirror.
  AC3. Every rule writer targets the canonical file.
  AC4. The loaded rule set is the canonical rule set.
  AC5. Golden-path evidence declares the file it actually hashed and counts
       `nids_rules`.
"""
from __future__ import annotations

import ast
import hashlib
import json
import sys
import tokenize
import warnings
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CANONICAL = REPO_ROOT / "configs" / "Rules.json"
MIRROR = REPO_ROOT / "config" / "Rules.json"

sys.path.insert(0, str(REPO_ROOT))


def _slug(path: Path) -> str:
    return str(path).replace("\\", "/")


# ── AC1: the mirror cannot drift ───────────────────────────────────────────

def test_legacy_mirror_is_identical_to_the_canonical_rule_set():
    assert MIRROR.exists(), "packaging checks still require the legacy mirror path"
    canonical_bytes = CANONICAL.read_bytes()
    assert MIRROR.read_bytes() == canonical_bytes, (
        "config/Rules.json diverged from configs/Rules.json; delete or refresh it "
        f"(sha256 canonical={hashlib.sha256(canonical_bytes).hexdigest()[:16]}, "
        f"mirror={hashlib.sha256(MIRROR.read_bytes()).hexdigest()[:16]})"
    )


# ── AC2: no rule loader reads the mirror ───────────────────────────────────

def _code_without_comments(path: Path) -> str:
    """Source text with # comments removed, so prose cannot trip the check."""
    with path.open("r", encoding="utf-8") as handle:
        tokens = [
            token.string
            for token in tokenize.generate_tokens(handle.readline)
            if token.type != tokenize.COMMENT
        ]
    return " ".join(tokens)


def _string_constants(path: Path) -> list[str]:
    """Every string literal except docstrings, i.e. actual path construction."""
    with warnings.catch_warnings():
        # Some scanned modules still carry legacy non-raw regex literals; their
        # SyntaxWarnings are not this contract's business.
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc is not None:
                docstrings.add(doc)
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value not in docstrings
    ]


def test_no_rule_loader_reads_the_legacy_mirror():
    scanned = 0
    for rel in (
        "tools/aegisctl/api/control_api.py",
        "tools/golden_path_evidence.py",
        "tools/aegisctl/config.py",
        "tools/aegisctl/utils.py",
        "scripts/aegis_console.py",
        "scripts/aegis_rules.py",
        "brain/windows_brain.py",
    ):
        path = REPO_ROOT / rel
        scanned += 1
        code = _code_without_comments(path)
        assert '"config" / "Rules.json"' not in code, f"{rel} joins config/ with Rules.json"
        assert "'config' / 'Rules.json'" not in code, f"{rel} joins config/ with Rules.json"
        for literal in _string_constants(path):
            assert "config/Rules.json" not in literal, f"{rel} loads rules from the mirror"
    assert scanned >= 7


def test_rule_module_paths_resolve_to_the_canonical_file():
    from tools.aegisctl import config as aegisctl_config

    assert _slug(aegisctl_config.RULES_FILE).endswith("/configs/Rules.json")
    assert _slug(aegisctl_config.DISABLED_RULES_FILE).endswith("/disabled_rules.json")


# ── AC3: writers target the canonical file ─────────────────────────────────

def test_rule_writers_target_the_canonical_file():
    from tools.aegisctl import config as aegisctl_config
    from tools.aegisctl import utils as aegisctl_utils

    assert _slug(aegisctl_utils.RULES_FILE) == _slug(aegisctl_config.RULES_FILE)

    cli = (REPO_ROOT / "tools" / "aegisctl.py").read_text(encoding="utf-8")
    assert 'TOOLS_DIR.parent / "configs" / "Rules.json"' in cli, (
        "aegisctl rule add/update/delete must write the canonical file"
    )


def test_console_and_rules_scripts_use_the_canonical_file():
    for rel in ("scripts/aegis_console.py", "scripts/aegis_rules.py"):
        source = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert '"configs"' in source and '"Rules.json"' in source, rel


# ── AC4: the loaded set is the canonical set ───────────────────────────────

def test_control_api_loads_exactly_the_canonical_rules():
    from tools.aegisctl.api import control_api

    loaded = control_api.load_rules()
    expected = json.loads(CANONICAL.read_text(encoding="utf-8"))
    assert loaded == expected, "the control plane served a rule set that is not the authority"

    # The mirror used to differ here; pin the two patterns it lied about.
    by_id = {rule["rule_id"]: rule for rule in loaded["nids_rules"]}
    assert by_id["R2004"]["regex_pattern"] == r"certutil(?:\.exe)?\b.*(?:-urlcache|-f)\b"
    r1005 = by_id["R1005"]["regex_pattern"]
    assert r1005.startswith(r"(?:^|[\\/])hosts$") and r1005.endswith(r"hosts$")


# ── AC5: evidence describes what it hashed ─────────────────────────────────

def test_golden_path_evidence_hashes_the_file_it_claims():
    source = (REPO_ROOT / "tools" / "golden_path_evidence.py").read_text(encoding="utf-8")
    assert 'REPO / "config" / "Rules.json"' not in source
    assert 'rules = REPO / "configs" / "Rules.json"' in source
    assert '"path": "configs/Rules.json"' in source
    assert 'data.get("nids_rules"' in source, (
        "the evidence must count the canonical nids_rules key, not a legacy 'rules' key"
    )
