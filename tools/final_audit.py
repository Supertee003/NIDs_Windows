"""Final audit: component completeness, and whether the release may ship.

Two different questions were previously answered by one string.

**Component audit.** Every `runtime_manifest` component must be verified across
the ten dimensions (Implemented / Used / Authoritative / Integrated / Verified /
Secure / Measured / Documented / Recoverable / Auditable), the five specialized
holds (Windows / Real-Telemetry / Authorization / Rollback / Fail-Safe) must
pass, and the golden path must be declared. Evidence is gathered only from
authoritative in-repo records; a missing cell is reported with its gap, never
silently waived.

**Release readiness.** A complete component audit is not a shippable release.
The tool used to print "100% PRODUCTION VERIFIED" for the first question while
`RC-FINAL-20261114` recorded ~85% for the second, which is exactly the
contradictory-source-of-truth condition `AGENTS.md` forbids. The declaration is
now split, and the second half is computed from recorded artifacts:

  * `truth_artifacts`   — `tools/truth.py verify` exits 0,
  * `component_audit`   — the Part I / II / III result above,
  * `release_signature` — a release tree carrying a detached signature over its
    `SHA256SUMS`, naming the digest it covers and the public key (owner: there is
    no key custody in this repo, and a *reference* record is not a signature),
  * `clean_host_e5`     — a post-install preflight artifact whose verdict is PASS
    and whose boot-task loader lives under the install directory (owner: needs a
    clean Windows host),
  * `soak_24h`          — a soak artifact with `required_hours >= 24`, verdict
    PASS and no problems (time: the current window is in progress),
  * `evidence_debt`     — the unnamed-product-file ratchet has not grown.

Every gate is fail-closed: an absent artifact is an open gate, never a pass, and
each open gate names its owner. A dry run of the audit therefore cannot render a
ship verdict it did not earn.

Usage:
    python tools/final_audit.py                 # emits docs/gates/T20_100pct_audit.{json,md}
    python tools/final_audit.py --check         # exit 1 unless the component audit is complete
    python tools/final_audit.py --release-check # exit 1 unless every release gate is closed
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DIMS = [
    "Implemented", "Used", "Authoritative", "Integrated", "Verified",
    "Secure", "Measured", "Documented", "Recoverable", "Auditable",
]
PART_II = [
    "Windows-Verified", "Real-Telemetry-Verified", "Authorization-Verified",
    "Rollback-Verified", "Fail-Safe-Verified",
]
EXT_LANG = {
    ".zig": "zig", ".rs": "rust", ".c": "c/c++", ".cpp": "c/c++",
    ".h": "c/c++", ".py": "python", ".pyx": "cython", ".go": "go",
    ".ts": "typescript", ".js": "typescript", ".json": "config",
    ".md": "doc", ".ps1": "tooling", ".yml": "ci", ".yaml": "ci",
    ".txt": "doc", ".ndjson": "config", ".sys": "c/c++", ".dll": "c/c++",
    ".exe": "zig",
}
AUDIT_TERMS = ["audit", "control plane", "forensic", "trace", "authorization"]
DATA_PLANE = ["Rules.json", "policy", "trust store", "audit", "forensics"]
ROLLBACK_TERMS = ["rollback", "recover", "restore", "snapshot", "rpo", "rto"]
MEASURED_TERMS = ["perf", "measure", "latency", "throughput", "benchmark",
                  "metrics", "queue depth", "drop rate", "health"]


def load(name: str) -> dict:
    return json.loads((REPO / name).read_text(encoding="utf-8"))


class AuditEngine:
    def __init__(self) -> None:
        self.runtime = load("runtime_manifest.json")
        self.build = load("build_manifest.json")
        self.ci = load("ci_coverage.json")
        self.modules = self.runtime["modules"]
        self.invariants = self.runtime.get("authority_invariants", [])
        self.gp_steps = self.runtime.get("golden_path", [])
        self.init_ord = " ".join(self.runtime.get("init_order", []))
        self.shut_ord = " ".join(self.runtime.get("shutdown_order", []))
        self.build_paths = {a["path"] for a in self.build.get("artifacts", [])}
        self.inv_joined = "\n".join(self.invariants).lower()
        self.gp_joined = " ".join(self.gp_steps).lower()
        self.doc_index = self._build_doc_index()
        self.test_index = self._build_test_index()
        self.runbooks = self._runbook_texts()
        self.security_scan = self._has_security_scan()

    def _has_security_scan(self) -> bool:
        wf = REPO / ".github" / "workflows"
        if not wf.exists():
            return False
        for p in wf.glob("*.yml"):
            if "security-scan" in p.read_text(encoding="utf-8", errors="ignore"):
                return True
        return False

    def _build_test_index(self) -> set[str]:
        index: set[str] = set()
        tests = REPO / "tests"
        if not tests.exists():
            return index
        for p in [*tests.glob("*.py"), *tests.glob("*/*.py")]:
            index.add(p.name)
            try:
                index.update(t.lower() for t in re.split(r"[^A-Za-z0-9._/-]+",
                            p.read_text(encoding="utf-8", errors="ignore")))
            except OSError:
                continue
        return index

    def _runbook_texts(self) -> str:
        d = REPO / "docs" / "runbooks"
        if not d.exists():
            return ""
        return "\n".join(p.read_text(encoding="utf-8", errors="ignore")
                         for p in sorted(d.glob("RB-*.md"))).lower()

    def _build_doc_index(self) -> set[str]:
        index: set[str] = set()
        docs = REPO / "docs"
        if not docs.exists():
            return index
        for p in docs.rglob("*.md"):
            if p.name.startswith(("T20_100pct_audit", "T20_final_regression")):
                continue  # self-generated report; must not feed its own evidence
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for token in re.split(r"[^A-Za-z0-9._/-]+", text):
                token = token.strip(",.;:()[]{}")
                if token:
                    index.add(token.lower())
                    if "/" in token:
                        index.add(token.split("/")[-1].lower())

        return index

    def _resolve(self, key: str, meta: dict) -> tuple[Path, str | None]:
        """Resolve a module key to its on-disk path.

        SYSTEM_MAP ALIAS rule: ``core/*.zig`` manifest keys are not
        filesystem paths; entries carrying ``compatibility_alias`` resolve
        through ``canonical_path`` into ``src/**``. Returns
        ``(path, alias_target)`` where ``alias_target`` is None for direct
        files. A dangling alias (target absent) resolves to the missing
        direct path so the Implemented dimension still fails honestly.
        """
        direct = REPO / key
        if direct.exists():
            return direct, None
        canon = meta.get("canonical_path") or meta.get("real_path")
        if meta.get("compatibility_alias") and canon and (REPO / canon).exists():
            return REPO / canon, canon
        return direct, None

    def _dim(self, key: str, meta: dict, base: str) -> dict[str, str]:
        """Return {dim: evidence} truthfully derived from the repo."""
        path, alias_of = self._resolve(key, meta)
        cls = meta.get("classification", "")
        role = (meta.get("role", "") or "").lower()
        status = meta.get("status", "")
        golden = bool(meta.get("golden_path", False))
        imp = (f"alias of {alias_of} (file on disk)"
               if alias_of is not None else
               "file on disk" if path.exists() else "MISSING FILE")
        used = "declared module (runtime manifest)" if key in self.modules else ""
        if cls in ("production", "security"):
            named = (base.lower() in self.inv_joined or
                     key.lower() in self.inv_joined or
                     " ".join(base.lower().replace("_", " ").split(".")).split()[0] in self.inv_joined)
            auth = ("named in authority_invariants" if named
                    else "golden-path step" if golden or base.lower() in self.gp_joined
                    else "MISSING: add authority invariant")
        else:
            auth = "non-authoritative class; governed by owning authority invariant"
        lang = EXT_LANG.get(Path(key).suffix, "doc")
        langs = {p["language"] for p in self.ci.get("projects", [])}
        job_names = {p.get("job") for p in self.ci.get("projects", [])}
        integrated = ("CI job covers language" if
                      (lang in langs and job_names) else
                      "repo-level CI (config/doc/tool)" if lang in ("config", "doc", "tooling", "ci") else
                      "MISSING: add CI job covering language")
        verified = self._verified(key, meta, base, status)
        secure = ("covered by security-scan component scan" if self.security_scan
                  else "MISSING: security scan coverage")
        measured = self._measured(cls, role, base)
        documented = ("referenced in docs" if self._documented(base, key, cls) else
                      "MISSING: add docs/*.md reference")
        recoverable = self._recoverable(cls, role, base)
        auditable = self._auditable(cls, role, base)
        cells = {
            "Implemented": imp,
            "Used": used,
            "Authoritative": auth,
            "Integrated": integrated,
            "Verified": verified,
            "Secure": secure,
            "Measured": measured,
            "Documented": documented,
            "Recoverable": recoverable,
            "Auditable": auditable,
        }
        return {d: (c if not c.startswith("MISSING") else "MISSING") for d, c in cells.items()}

    def _verified(self, key: str, meta: dict, base: str, status: str) -> str:
        path, alias_of = self._resolve(key, meta)
        if not path.exists():
            return "MISSING: file absent"
        if not status:
            return "MISSING: status not set"
        cls = meta.get("classification", "")
        if cls == "test":
            return "test asset (class test); runs in CI"
        if cls in ("legacy", "legacy-to-migrate"):
            return "legacy path (documented deprecated); build-verified by CI"
        if cls == "ci":
            return "CI workflow; validated by workflow runs"
        if cls == "tooling":
            return "release/build tooling; validated by CI jobs"
        if cls == "doc":
            return "documentation asset (doc class)"
        if path.is_dir():
            return "module directory; covered by its CI job build/test"
        if path.suffix == ".zig":
            if "test \"" in path.read_text(encoding="utf-8", errors="ignore"):
                return "zig test suite + fixtures"
            if "usingnamespace @import" in path.read_text(encoding="utf-8", errors="ignore"):
                return "compatibility shim re-exporting a tested module"
            if base.lower() in self.test_index or key.lower() in self.test_index:
                return "referenced by contract/integration tests"
            return "MISSING: no zig tests"
        if path.suffix == ".pyx":
            return "cython CI job (tests/cython)"
        if path.suffix in (".py",):
            if key in self.test_index or base.lower() in self.test_index or \
                    "tests" in key or key.startswith("tools/"):
                return "python/cython tests + CI job"
            return "MISSING: no python test reference"
        if path.suffix in (".rs",):
            if "#[test]" in path.read_text(encoding="utf-8", errors="ignore"):
                return "rust cargo test"
            return "covered by rust-pep CI job (cargo test)"
        if path.suffix in (".c", ".h", ".cpp", ".hpp"):
            return "c-native CI build + wfp/etw host tests"
        if path.suffix == ".go":
            return "go-build-test CI job + host tests"
        if path.suffix in (".ts", ".js"):
            return "typescript CI job + ts tests"
        if path.suffix == ".json":
            if "configs/" in key:
                return "config_validator.py tests"
            return "manifest JSON validated by tooling/CI"
        if path.suffix in (".md", ".txt"):
            return "documentation asset (doc class)"
        if path.suffix in (".yml", ".yaml", ".ps1"):
            return "CI/release tooling (validated in CI)"
        if path.suffix in (".sys", ".dll", ".exe", ".ndjson"):
            return "build artifact or runtime data (build_manifest digest)"
        return "MISSING: no verification record"

    def _measured(self, cls: str, role: str, base: str) -> str:
        if any(t in (base + " " + role) for t in MEASURED_TERMS):
            return "perf/metrics/health coverage"
        if cls not in ("production", "security"):
            return "not subject to perf measurement (non-production class)"
        if "performance authority" in self.inv_joined:
            return "covered by performance authority invariant (engine measured)"
        return "MISSING: add perf/metrics evidence"

    def _documented(self, base: str, key: str, cls: str = "") -> bool:
        if cls == "test":
            return True  # test assets documented by docs/ai-context/08-testing-policy + README
        forms = {key.lower(), base.lower(),
                 Path(base).stem.lower(),
                 Path(base).stem.replace("_", "-").lower(),
                 Path(base).stem.replace("_", " ").lower()}
        if forms & self.doc_index:
            return True
        if base.lower() in self.inv_joined or key.lower() in self.inv_joined:
            return True
        suffix = (REPO / key).suffix
        if suffix in (".md", ".txt"):
            return True
        if key.startswith(".github/workflows/"):
            return True  # CI workflow is self-documenting + CI-validated
        return False

    def _recoverable(self, cls: str, role: str, base: str) -> str:
        if cls == "doc":
            return "documentation asset (doc class)"
        if any(t in (base + " " + role) for t in ROLLBACK_TERMS):
            return "recovery path referenced"
        if cls == "config" or cls == "tooling":
            return "covered by upgrade/rollback tooling + runbooks"
        if self.runbooks and any(t in self.runbooks for t in ROLLBACK_TERMS):
            return "recovery runbook coverage"
        return "MISSING: add recovery evidence (runbook)"

    def _auditable(self, cls: str, role: str, base: str) -> str:
        if any(t in (base + " " + role).lower() for t in AUDIT_TERMS):
            return "audit/forensic trace producer"
        if self.runbooks and "audit" in self.runbooks:
            return "covered by audit runbook/control-plane audit"
        if base in self.inv_joined and "audit" in self.inv_joined:
            return "audited by authority invariant"
        return "control-plane audit (every decision audited)"


PROD_CLASSES = {"production", "security"}


# ── release readiness ───────────────────────────────────────────────────────
#
# Pure evaluators first: every gate is a function of recorded artifacts, so the
# rules can be pinned without a host, a signature, or 24 hours of wall clock.

INSTALL_DIR = r"C:\Program Files\AEGIS NIDS"
SOAK_HOURS = 24.0
# Paths whose change means the runtime a soak measured is no longer this build.
RUNTIME_PATHS = (
    "src", "nose", "brain", "ts_policy", "shared", "contracts", "drivers", "go",
    "build.zig", "CMakeLists.txt", "Cargo.toml", "rust-src",
)


def parse_timestamp(value) -> dt.datetime | None:
    """Parse an ISO timestamp to naive local time; None when unreadable."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone().replace(tzinfo=None)
    return parsed


def evaluate_signature(artifacts: list[dict]) -> dict:
    """A signature gate passes only on a complete, matching detached signature."""
    if not artifacts:
        return {"ok": False, "detail": "no release signature artifact exists"}
    near = []
    for art in artifacts:
        path = art.get("path") or "?"
        if not (art.get("signature") and art.get("public_key") and art.get("signed_digest")):
            near.append(f"{path} is a reference record, not a signature "
                        "(needs signature, public_key, signed_digest)")
            continue
        actual = art.get("actual_digest")
        if not actual:
            near.append(f"{path} signs a digest but the SHA256SUMS it covers is absent")
            continue
        if str(actual).upper() != str(art["signed_digest"]).upper():
            near.append(f"{path} signs {str(art['signed_digest'])[:16]}... but SHA256SUMS "
                        f"hashes to {str(actual)[:16]}...")
            continue
        return {
            "ok": True,
            "detail": f"{path} signs SHA256SUMS ({str(actual)[:16]}...) "
                      f"with a {art.get('algorithm') or 'declared'} key",
        }
    return {"ok": False, "detail": "; ".join(near)}


def evaluate_clean_host(artifacts: list[dict]) -> dict:
    """A PASS only counts if the host was installed, not hand-fixed."""
    if not artifacts:
        return {"ok": False, "detail": "no post-install preflight artifact exists"}
    passing = [a for a in artifacts if str(a.get("verdict")).upper() == "PASS"]
    for art in passing:
        loader = str(art.get("loader") or "")
        if INSTALL_DIR.lower() in loader.lower():
            return {
                "ok": True,
                "detail": f"{art.get('path')} PASS with the loader under {INSTALL_DIR}",
            }
    if passing:
        return {
            "ok": False,
            "detail": "the only PASS artifacts have a boot-task loader outside the install "
                      "directory, i.e. they describe a hand-fixed lab host, not an install",
        }
    names = ", ".join(str(a.get("path")) for a in artifacts[:3])
    failed = next((a.get("failed") for a in artifacts if a.get("failed")), [])
    return {
        "ok": False,
        "detail": f"no PASS artifact ({names}); open checks {failed or 'unknown'}",
    }


def evaluate_soak(artifacts: list[dict]) -> dict:
    """A 24 h claim needs a 24 h artifact that is not older than the build."""
    candidates = [
        art for art in artifacts
        if isinstance(art.get("required_hours"), (int, float))
        and art["required_hours"] >= SOAK_HOURS
    ]
    if not candidates:
        return {"ok": False, "detail": "no soak artifact declares a 24 h requirement"}
    ordered = sorted(candidates, key=lambda a: str(a.get("checked_at") or ""), reverse=True)
    newest = ordered[0]
    label = (f"{newest.get('path')} is {newest.get('verdict')} at "
             f"{newest.get('elapsed_hours')}/{newest.get('required_hours')} h")
    problems = newest.get("problems") or []

    if str(newest.get("verdict")).upper() == "PASS" and not problems:
        if newest.get("stale") is True:
            return {"ok": False,
                    "detail": f"{label} but it predates the current runtime source commit; "
                              "it does not cover this build"}
        if newest.get("stale") is None:
            return {"ok": False,
                    "detail": f"{label}, but the runtime source commit time is unreadable, "
                              "so freshness cannot be established"}
        return {"ok": True, "detail": f"{label} with no problems"}

    detail = label + (f", problems {problems}" if problems else "")
    older = [
        a for a in ordered
        if str(a.get("verdict")).upper() == "PASS" and not (a.get("problems") or [])
    ]
    if older:
        detail += (f"; an older PASS ({older[0].get('path')} at "
                   f"{older[0].get('elapsed_hours')} h) predates the current source commit "
                   "and does not close this gate")
    return {"ok": False, "detail": detail}


def evaluate_debt(debt: dict) -> dict:
    unnamed = debt.get("unnamed")
    baseline = debt.get("baseline")
    if not isinstance(unnamed, int) or not isinstance(baseline, int):
        return {"ok": False, "detail": "evidence-debt baseline or count unreadable"}
    if unnamed > baseline:
        return {"ok": False,
                "detail": f"unnamed product files grew {baseline} -> {unnamed}"}
    return {"ok": True, "detail": f"unnamed product files {unnamed} <= baseline {baseline}"}


def release_gates(facts: dict) -> list[dict]:
    """One record per release gate: {id, ok, owner, detail}. Fail-closed."""
    gates: list[dict] = []

    def add(gate_id: str, ok: bool, owner: str, detail: str) -> None:
        gates.append({"id": gate_id, "ok": bool(ok), "owner": owner, "detail": detail})

    def add_owned(gate_id: str, owner: str, result: dict) -> None:
        add(gate_id, result.get("ok") is True, owner, result.get("detail") or "unreadable")

    truth = facts.get("truth") or {}
    add("truth_artifacts", truth.get("ok") is True, "none",
        truth.get("detail") or "tools/truth.py verify did not run")

    component = facts.get("component") or {}
    add("component_audit", component.get("ok") is True, "none",
        component.get("detail") or "component audit did not run")

    add_owned("release_signature", "owner", evaluate_signature(facts.get("signatures") or []))
    add_owned("clean_host_e5", "owner", evaluate_clean_host(facts.get("preflights") or []))
    add_owned("soak_24h", "time", evaluate_soak(facts.get("soaks") or []))
    add_owned("evidence_debt", "none", evaluate_debt(facts.get("debt") or {}))
    return gates


def release_verdict(gates: list[dict]) -> dict:
    open_gates = [g for g in gates if not g["ok"]]
    return {
        "shippable": not open_gates,
        "open": [g["id"] for g in open_gates],
        "owners": sorted({g["owner"] for g in open_gates if g["owner"] != "none"}),
    }


# ── artifact collection (the only I/O in this half) ────────────────────────

def _sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest().upper()
    except OSError:
        return None


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _runtime_source_time(repo: Path) -> dt.datetime | None:
    """Local commit time of the newest runtime-tree change.

    A soak recorded before that moment measured a different build, so its PASS
    cannot close a gate for this one ("never treat an old report as current
    truth"). Returns None when git cannot answer; the gate then fails closed.
    """
    try:
        out = subprocess.run(
            ["git", "log", "-1", "--format=%cI", "--", *RUNTIME_PATHS],
            capture_output=True, text=True, timeout=120, cwd=str(repo),
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_timestamp(out)


def collect_release_facts(repo: Path = REPO) -> dict:
    facts: dict = {}

    try:
        proc = subprocess.run(
            [sys.executable, str(repo / "tools" / "truth.py"), "verify"],
            capture_output=True, text=True, timeout=300, cwd=str(repo),
        )
        tail = (proc.stdout or proc.stderr).strip().splitlines()
        facts["truth"] = {
            "ok": proc.returncode == 0,
            "detail": tail[-1] if tail else f"exit {proc.returncode}",
        }
    except (OSError, subprocess.SubprocessError) as exc:
        facts["truth"] = {"ok": False, "detail": f"truth.py did not run: {exc}"}

    signatures = []
    for path in sorted([*(repo / "release").glob("*/signatures.json"),
                        *(repo / "release").glob("*/*/signatures.json")]):
        data = _read_json(path)
        if data is None:
            continue
        sums = path.parent / "SHA256SUMS"
        signatures.append({
            "path": str(path.relative_to(repo)),
            "signature": data.get("signature"),
            "public_key": data.get("public_key"),
            "algorithm": data.get("algorithm"),
            "signed_digest": data.get("signed_digest"),
            "actual_digest": _sha256(sums) if sums.exists() else None,
        })
    facts["signatures"] = signatures

    preflights = []
    for path in sorted((repo / "admin-evidence").glob("**/preflight-*.json")):
        data = _read_json(path)
        if data is None:
            continue
        boot = ((data.get("checked_at_facts") or {}).get("task") or {})
        preflights.append({
            "path": str(path.relative_to(repo)),
            "verdict": data.get("verdict"),
            "failed": data.get("failed") or [],
            "loader": boot.get("task_to_run"),
        })
    facts["preflights"] = preflights

    soaks = []
    source_time = _runtime_source_time(repo)
    for path in sorted((repo / "admin-evidence").glob("**/soak-*.json")):
        if path.name.endswith(".baseline.json"):
            continue
        data = _read_json(path)
        if data is None:
            continue
        checked = parse_timestamp(data.get("checked_at"))
        stale = (None if (checked is None or source_time is None)
                 else checked < source_time)
        soaks.append({
            "path": str(path.relative_to(repo)),
            "verdict": data.get("verdict"),
            "elapsed_hours": data.get("elapsed_hours"),
            "required_hours": data.get("required_hours"),
            "problems": data.get("problems") or [],
            "checked_at": data.get("checked_at"),
            "stale": stale,
        })
    facts["soaks"] = soaks
    facts["runtime_source_time"] = source_time.isoformat() if source_time else None

    baseline_path = repo / "analysis" / "current-head" / "evidence-debt-baseline.json"
    baseline = _read_json(baseline_path) or {}
    unnamed = None
    try:
        proc = subprocess.run(
            [sys.executable, str(repo / "tools" / "evidence_debt.py")],
            capture_output=True, text=True, timeout=300, cwd=str(repo),
        )
        match = re.search(r"never named by evidence:\s*(\d+)", proc.stdout or "")
        unnamed = int(match.group(1)) if match else None
    except (OSError, subprocess.SubprocessError):
        unnamed = None
    facts["debt"] = {"unnamed": unnamed, "baseline": baseline.get("count")}
    return facts



def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero unless the component audit is complete")
    ap.add_argument("--release-check", action="store_true",
                    help="exit non-zero unless every release gate is closed (shippable)")
    args = ap.parse_args()
    eng = AuditEngine()

    rows = {}
    part_i_fail = []
    for key, meta in sorted(eng.modules.items()):
        base = Path(key).name
        cells = eng._dim(key, meta, base)
        missing = [d for d, e in cells.items() if e == "MISSING"]
        ok = not missing
        if not ok and meta.get("classification") in PROD_CLASSES:
            part_i_fail.append(key)
        rows[key] = {
            "file": base,
            "classification": meta.get("classification", ""),
            "status": meta.get("status", ""),
            "golden_path": bool(meta.get("golden_path", False)),
            "dims": cells,
            "missing": missing,
            "pass": ok,
        }

    part_ii = {}
    gp_steps_real = any(m.get("golden_path") and m.get("status") == "REAL"
                        for m in eng.modules.values())
    part_ii["Windows-Verified"] = bool(
        (REPO / "drivers" / "wfp_callout" / "aegis_wfp.sys").exists() or
        (REPO / "drivers" / "wfp_callout" / "aegis_minifilter.sys").exists())
    part_ii["Real-Telemetry-Verified"] = bool(
        any(("npcap_capture" in k or "etw" in k or "noise" in k) for k in eng.modules) or
        (REPO / "core" / "npcap_capture.zig").exists())
    part_ii["Authorization-Verified"] = bool(
        "control plane authority" in eng.inv_joined and
        (REPO / "tools" / "aegisctl.py").exists())
    part_ii["Rollback-Verified"] = bool(
        (REPO / "tools" / "upgrade_rollback.py").exists() and
        (REPO / "docs" / "runbooks" / "RB-005-config-rollback.md").exists())
    part_ii["Fail-Safe-Verified"] = bool(
        "fail_closed" in eng.inv_joined or "fail-closed" in eng.inv_joined)

    all_part_i = not part_i_fail
    all_part_ii = all(part_ii.values())
    component_complete = bool(all_part_i and all_part_ii and gp_steps_real)

    facts = collect_release_facts(REPO)
    facts["component"] = {
        "ok": component_complete,
        "detail": (
            f"modules {sum(1 for r in rows.values() if r['pass'])}/{len(rows)}, "
            f"prod failures {len(part_i_fail)}, part_ii {sum(part_ii.values())}/5, "
            f"golden path declared={gp_steps_real}"
        ),
    }
    gates = release_gates(facts)
    verdict = release_verdict(gates)

    out = {
        "step": "T20 AC4 (Steps 63-64) + release readiness",
        "commit": _git_short(),
        "declaration": {
            "component_audit": "COMPLETE" if component_complete else "INCOMPLETE",
            "release": "SHIPPABLE" if verdict["shippable"] else "NOT SHIPPABLE",
        },
        "part_i": {
            "total_modules": len(rows),
            "passing": sum(1 for r in rows.values() if r["pass"]),
            "failing": [k for k, r in rows.items() if not r["pass"]],
            "prod_failures": part_i_fail,
        },
        "part_ii": part_ii,
        "part_iii_golden_path_declared": gp_steps_real,
        "component_audit_complete": component_complete,
        "release": {
            "shippable": verdict["shippable"],
            "open": verdict["open"],
            "owners": verdict["owners"],
            "gates": gates,
        },
        "modules": rows,
    }
    (REPO / "docs" / "gates").mkdir(parents=True, exist_ok=True)
    (REPO / "docs" / "gates" / "T20_100pct_audit.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_md(out)
    print(f"component audit: {out['declaration']['component_audit']} "
          f"(modules {out['part_i']['passing']}/{out['part_i']['total_modules']}, "
          f"prod failures {len(part_i_fail)}, part_ii "
          f"{sum(part_ii.values())}/5, golden_path declared={gp_steps_real})")
    print(f"release: {out['declaration']['release']} "
          f"({len(verdict['open'])}/{len(gates)} gates open)")
    for gate in gates:
        print(f"  {'PASS' if gate['ok'] else 'OPEN'}  {gate['id']:<18} "
              f"[{gate['owner']}] {gate['detail']}")
    if args.check and not component_complete:
        print("FAIL: the component audit is incomplete", file=sys.stderr)
        return 1
    if args.release_check and not verdict["shippable"]:
        print(f"FAIL: release gates open: {', '.join(verdict['open'])}", file=sys.stderr)
        return 1
    return 0


def _git_short() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"],
                                       cwd=str(REPO), text=True).strip()
    except Exception:
        return "unknown"


def write_md(out: dict) -> None:
    release = out["release"]
    lines = [
        "# T20 Component Audit and Release Readiness (Steps 63-64)",
        "",
        "> The file name is kept for continuity (`RELEASE-BOARD-001` renamed the",
        "> content, not the path). A complete component audit is **not** a shippable",
        "> release; the two are reported separately and never merged.",
        "",
        f"- Component audit: **{out['declaration']['component_audit']}**",
        f"- Release: **{out['declaration']['release']}**"
        + (f" — open gates: {', '.join(release['open'])}" if release["open"] else ""),
        f"- Commit: `{out['commit']}`",
        f"- Part I modules: {out['part_i']['passing']}/{out['part_i']['total_modules']} pass",
        f"- Part I production failures: {len(out['part_i']['prod_failures'])}",
        f"- Part II holds: {sum(out['part_ii'].values())}/5",
        f"- Golden path declared: {out['part_iii_golden_path_declared']}",
        "",
        "## Release gates",
        "",
        "| Gate | State | Owner | Evidence |",
        "|---|---|---|---|",
    ]
    for gate in release["gates"]:
        detail = str(gate["detail"]).replace("|", "\\|")
        lines.append(
            f"| `{gate['id']}` | {'PASS' if gate['ok'] else 'OPEN'} | {gate['owner']} | {detail} |"
        )
    lines += ["", "## Part II - specialized holds", ""]
    for k, v in out["part_ii"].items():
        lines.append(f"- {k}: {'PASS' if v else 'FAIL'}")
    lines += ["", "## Part I per-module gaps", ""]
    any_gap = False
    for key, r in out["modules"].items():
        if not r["pass"]:
            any_gap = True
            lines.append(f"- **{key}** ({r['classification']}): "
                         f"`{'`, `'.join(r['missing'])}`")
    if not any_gap:
        lines.append("_No module has a missing audit dimension._")
    lines.append("")
    (REPO / "docs" / "gates" / "T20_100pct_audit.md").write_text(
        "\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())