"""NEG-001: forbidden language-boundary edges (negative controls).

Doc 02 section 3 forbids: Go->Rust PEP, Python->WFP, TS->WFP, CLI->WFP,
C++->policy authority, Shield->PEP authority, any all-to-all mesh.
AUTHORITY_MAP SHIELD_PEP exit criteria require a negative control that
fails if a PEP surface reappears in shield/.

Each test scans the live tree and fails on the forbidden construct.
Comment lines are stripped so historical notes ("never invokes X")
cannot false-positive. E2 (static) — complements live audits, does
not replace them.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
assert (REPO / "AGENTS.md").exists(), f"bad repo root: {REPO}"


def require(files, what: str):
    assert files, f"scan surface empty: {what}"
    return files


def code_lines(path: Path, comment: str = "#"):
    """Yield (lineno, code) with trailing comments removed."""
    for i, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.split(comment, 1)[0]
        if line.strip():
            yield i, line


def py_code(path: Path):
    """Code lines with # comments AND triple-quoted docstrings removed.

    Historical notes live in docstrings ("never invokes netsh"); they must
    not trip the effect scanner. Toggle-tracking handles multi-line blocks;
    per-line odd counts toggle state (single-line docstrings net to zero).
    """
    out = []
    in_doc = False
    for i, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw
        # blank out triple-quoted spans on this line, track block state
        while True:
            q = line.find('"""')
            q2 = line.find("'''")
            j = q if q2 < 0 or (q >= 0 and q < q2) else q2
            if j < 0:
                break
            mark = line[j:j + 3]
            k = line.find(mark, j + 3)
            if k >= 0:
                line = line[:j] + " " + line[k + 3:]
            else:
                line = line[:j]
                in_doc = not in_doc
                break
        if in_doc:
            continue
        code = line.split("#", 1)[0]
        if code.strip():
            out.append((i, code))
    return out


def hits(pattern: str, files, strip=None):
    found = []
    rx = re.compile(pattern)
    for f in files:
        lines = py_code(f) if f.suffix == ".py" else code_lines(f, strip or "#")
        for i, line in lines:
            if rx.search(line):
                found.append(f"{f.relative_to(REPO)}:{i}:{line.strip()[:100]}")
    return found


def test_shield_exports_no_pep_surface():
    """Shield must export only the screening symbol (SHIELD_PEP exit criterion)."""
    lib = REPO / "shield" / "src" / "lib.rs"
    text = lib.read_text(encoding="utf-8")
    assert "aegis_shield_screen" in text, "screening symbol missing"
    assert "aegis_pep_evaluate" not in text
    assert "aegis_pep_status_count" not in text
    assert "aegis_pep_version" not in text
    mangled = [l for l in text.splitlines() if "#[no_mangle]" in l]
    assert len(mangled) == 1, f"expected exactly 1 no_mangle export, got {len(mangled)}"
    assert not (REPO / "shield" / "src" / "windows_enforce.rs").exists(), \
        "duplicate WFP module must stay deleted"


def test_go_never_touches_pep_or_wfp():
    """Go is acquisition-only: no cgo, no PEP FFI, no WFP calls."""
    files = [p for p in (REPO / "nose").glob("*.go") if not p.name.endswith("_test.go")]
    files += list((REPO / "go").rglob("*.go"))
    require(files, "nose+go sources")
    bad = hits(r'import\s+"C"|aegis_pep|Fwpm[A-Z]|DeviceIoControl', files, strip="//")
    assert bad == [], f"forbidden Go->PEP/WFP edge: {bad}"


def test_python_never_executes_firewall_effect():
    """Brain/CLI may request via PEP; never netsh/iptables/WFP-filter mutation.

    NOTE: plain subprocess (tasklist, exact-path binaries) is legitimate
    process management, not a firewall effect — only effect patterns fail.
    """
    roots = [REPO / "brain", REPO / "tools" / "aegisctl.py", REPO / "tools" / "aegisctl"]
    files = []
    for r in roots:
        if r.is_file():
            files.append(r)
        else:
            files += [p for p in r.rglob("*.py") if ".venv" not in p.parts]
    require(files, "brain+cli sources")
    bad = hits(r"netsh|advfirewall|New-NetFirewallRule|Remove-NetFirewallRule"
               r"|iptables|Fwpm[A-Za-z]+\(|CDLL\([^)]*[Ff]wpuclnt", files)
    assert bad == [], f"forbidden Python->OS-enforcement edge: {bad}"


def test_cpp_and_c_have_no_policy_decisions():
    """Native adapters observe; PepDecision/policy authority lives in Rust PEP."""
    files = list((REPO / "bridge").glob("*.cpp")) + list((REPO / "bridge").glob("*.hpp"))
    files += list((REPO / "src" / "windows").glob("*.c"))
    require(files, "bridge+c sources")
    bad = hits(r"PepDecision|enforcement_decision|policy_authority_decide", files, strip="//")
    assert bad == [], f"forbidden C++->policy edge: {bad}"


def test_bridge_block_stays_fail_closed():
    """The legacy bridge ABI exists but must return -2, never a block."""
    text = (REPO / "bridge" / "aegis_ipc.cpp").read_text(encoding="utf-8")
    for fn in ("aegis_bridge_block_ip", "aegis_bridge_unblock_ip"):
        m = re.search(r"int32_t " + fn + r"\(.*?\)\s*\{(.*?)\n\}", text, re.S)
        assert m, f"{fn} implementation missing"
        assert "return -2" in m.group(1), f"{fn} must stay fail-closed (-2)"


def test_zig_pep_extern_lives_in_one_module():
    """Only pep_bindings.zig may declare the aegis_pep FFI; no sec_monitor extern."""
    hits_outside = []
    found = 0
    for p in (REPO / "src").rglob("*.zig"):
        if p.suffixes == [".zig", ".scaffold"]:
            continue
        if p.name.endswith(".scaffold"):
            continue
        found += 1
        for i, line in code_lines(p, "//"):
            if 'extern "sec_monitor"' in line:
                hits_outside.append(f"{p.relative_to(REPO)}:{i}")
            if 'extern "aegis_pep"' in line and p.name != "pep_bindings.zig":
                hits_outside.append(f"{p.relative_to(REPO)}:{i}")
    assert found > 100, f"zig scan surface too small: {found}"
    assert hits_outside == [], f"PEP FFI outside pep_bindings.zig: {hits_outside}"


def test_typescript_has_no_native_enforcement_dep():
    """TS stays advisory: no FFI/native/WFP packages in dependencies."""
    import json
    pkg = json.loads((REPO / "ts_policy" / "package.json").read_text(encoding="utf-8"))
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    banned = [n for n in deps if re.search(r"ffi|napi|wfp|firewall|edge-js", n, re.I)]
    assert banned == [], f"forbidden TS native deps: {banned}"


def test_control_plane_has_no_unauthenticated_tcp_transport():
    """The daemon never listens on TCP, so no client path may send control
    commands over unauthenticated TCP (T1-NET-019). The web console binds
    loopback only."""
    client = (REPO / "tools" / "aegisctl" / "client.py").read_text(encoding="utf-8")
    assert "create_connection" not in client, "TCP client branch must stay removed"
    assert "_send_tcp" not in client, "TCP send path must stay removed"
    dash = (REPO / "tools" / "aegisctl" / "web_dashboard" / "app.py").read_text(encoding="utf-8")
    assert 'host="0.0.0.0"' not in dash and "host='0.0.0.0'" not in dash, (
        "web console must bind loopback only"
    )


def test_quarantined_orchestrators_have_no_production_importers():
    """dispatcher.zig, dispatcher_phase_b.zig and reliability/lifecycle.zig
    are test-harness orchestrators. The daemon (main/service/daemon,
    pipeline, platform, control) must never import them; production flow
    is pipeline/event_processor.zig + policy/action_dispatcher.zig."""
    prod_roots = ["src/main.zig", "src/daemon.zig"]
    prod_dirs = ["src/pipeline", "src/platform", "src/control", "src/capture",
                 "src/detection", "src/forensic", "src/policy", "src/windows"]
    banned = []
    checked = 0
    for root in prod_roots:
        p = REPO / root
        if not p.exists():
            continue
        checked += 1
        for i, line in code_lines(p, "//"):
            if re.search(r"policy/dispatcher(?:_phase_b)?\.zig|reliability/lifecycle\.zig", line):
                banned.append(f"{root}:{i}:{line.strip()[:100]}")
    for d in prod_dirs:
        for p in (REPO / d).rglob("*.zig"):
            if p.suffixes == [".zig", ".scaffold"] or p.name.endswith(".scaffold"):
                continue
            if p.name in {"dispatcher.zig", "dispatcher_phase_b.zig", "lifecycle.zig"}:
                continue
            checked += 1
            for i, line in code_lines(p, "//"):
                if re.search(r"policy/dispatcher(?:_phase_b)?\.zig|reliability/lifecycle\.zig", line):
                    banned.append(f"{p.relative_to(REPO)}:{i}:{line.strip()[:100]}")
    assert checked > 50, f"zig prod scan surface too small: {checked}"
    assert banned == [], f"production imports quarantined orchestrator: {banned}"


def test_demo_adapters_have_no_production_importers():
    """REG-STUB-045: windows_adapters.zig (EtwProcessSource /
    FimReadDirectorySource / RegNotifySource) emits nothing on any platform
    — production telemetry is etw_realtime + fim.zig/fim_native.c +
    registry_monitor.zig wired in daemon.zig. Only tests/cli may import it;
    a production importer would wire a silent stub expecting live events
    (the re-arm confusion class)."""
    prod_roots = ["src/main.zig", "src/daemon.zig"]
    prod_dirs = ["src/pipeline", "src/platform", "src/control", "src/capture",
                 "src/detection", "src/forensic", "src/policy", "src/windows",
                 "src/contract", "src/core"]
    banned = []
    checked = 0
    for root in prod_roots:
        p = REPO / root
        if not p.exists():
            continue
        checked += 1
        for i, line in code_lines(p, "//"):
            if "windows_adapters.zig" in line or "windows/windows_adapters" in line:
                banned.append(f"{root}:{i}:{line.strip()[:100]}")
    for d in prod_dirs:
        for p in (REPO / d).rglob("*.zig"):
            if p.suffixes == [".zig", ".scaffold"] or p.name.endswith(".scaffold"):
                continue
            if p.name in {"windows_adapters.zig", "windows_adapters_cli.zig",
                          "registry_trie_cli.zig"}:
                continue
            checked += 1
            for i, line in code_lines(p, "//"):
                if "windows_adapters.zig" in line or "windows/windows_adapters" in line:
                    banned.append(f"{p.relative_to(REPO)}:{i}:{line.strip()[:100]}")
    assert checked > 50, f"zig prod scan surface too small: {checked}"
    assert banned == [], f"production imports demo adapters: {banned}"


def test_specimen_modules_have_no_production_importers():
    """REL-SPEC-050: src/reliability/reliability.zig is a G20-G33 design
    specimen (live homes: watchdog/fault_injection/security_check/
    latency_histogram, all wired in daemon.zig). Nothing in production may
    import it; T15 reads it as text. An importer would wire drill/specimen
    doubles (second ReliabilityWatchdog, stub SecurityCheck) into the live
    runtime."""
    prod_roots = ["src/main.zig", "src/daemon.zig"]
    prod_dirs = ["src/pipeline", "src/platform", "src/control", "src/capture",
                 "src/detection", "src/forensic", "src/policy", "src/windows",
                 "src/contract", "src/core", "src/reliability"]
    banned = []
    checked = 0
    for root in prod_roots:
        p = REPO / root
        if not p.exists():
            continue
        checked += 1
        for i, line in code_lines(p, "//"):
            if "reliability/reliability" in line:
                banned.append(f"{root}:{i}:{line.strip()[:100]}")
    for d in prod_dirs:
        for p in (REPO / d).rglob("*.zig"):
            if p.suffixes == [".zig", ".scaffold"] or p.name.endswith(".scaffold"):
                continue
            if p.name == "reliability.zig":
                continue
            checked += 1
            for i, line in code_lines(p, "//"):
                if "reliability/reliability" in line:
                    banned.append(f"{p.relative_to(REPO)}:{i}:{line.strip()[:100]}")
    assert checked > 50, f"zig prod scan surface too small: {checked}"
    assert banned == [], f"production imports specimen module: {banned}"


def test_federation_family_has_no_production_importers():
    """FED-TIDY-058: src/federation/* (codec/coord/TLS/TCP/bench/aggregator/
    node_registry) is test-only and unwired: the daemon graph never imports
    it, the control plane reports standalone, and escalate() has no
    transport. Bench/CLI scaffolding (core/perf_benchmark,
    core/integration_test, tests/*) is the only allowed importer; a
    production importer would silently attach an unverified cluster path
    (STEP 53) to the live runtime. The Project 4+ verdict may rewire this
    pin behind a design slice."""
    prod_roots = ["src/main.zig", "src/daemon.zig"]
    prod_dirs = ["src/pipeline", "src/platform", "src/control", "src/capture",
                 "src/detection", "src/forensic", "src/policy", "src/windows",
                 "src/contract", "src/core", "src/reliability"]
    allowed_files = {"perf_benchmark.zig", "integration_test.zig"}
    banned = []
    checked = 0
    for root in prod_roots:
        p = REPO / root
        if not p.exists():
            continue
        checked += 1
        for i, line in code_lines(p, "//"):
            if "federation/" in line:
                banned.append(f"{root}:{i}:{line.strip()[:100]}")
    for d in prod_dirs:
        for p in (REPO / d).rglob("*.zig"):
            if p.suffixes == [".zig", ".scaffold"] or p.name.endswith(".scaffold"):
                continue
            if p.name in allowed_files:
                continue
            if p.parent.name == "federation":
                continue
            checked += 1
            for i, line in code_lines(p, "//"):
                if "federation/" in line:
                    banned.append(f"{p.relative_to(REPO)}:{i}:{line.strip()[:100]}")
    assert checked > 50, f"zig prod scan surface too small: {checked}"
    assert banned == [], f"production imports federation family: {banned}"


def test_legacy_tcp_listener_stays_dead():
    """T1-NET-019 leftover: src/core/nids_analyze.zig contains a 0.0.0.0 TCP
    listener (tcp_listener, spawned by analyze_packets, itself spawned only
    by the orphaned nids_main.main). The production daemon (main.zig ->
    win32_service -> daemon.zig) never runs that chain, and build.zig never
    builds nids_main as an executable — the control plane stays named-pipe
    only. Fail if the listener gains a new spawner, the chain gains a new
    caller, or the legacy entry becomes reachable from production."""
    zig_files = [p for p in (REPO / "src").rglob("*.zig")
                 if p.suffixes != [".zig", ".scaffold"] and not p.name.endswith(".scaffold")]
    require(zig_files, "zig sources")
    # 1. tcp_listener is spawned exactly once (analyze_packets, legacy flow).
    spawns = [h for h in hits(r"tcp_listener", zig_files, strip="//")
              if "fn tcp_listener(" not in h]
    assert len(spawns) == 1 and "nids_analyze.zig" in spawns[0], (
        f"tcp_listener spawner changed: {spawns}"
    )
    # 2. analyze_packets is entered only by nids_main.main (orphan entry).
    entries = [h for h in hits(r"analyze_packets", zig_files, strip="//")
               if "fn analyze_packets(" not in h
               and "analyze_packets not called in test mode" not in h
               and "registered separately in analyze_packets(" not in h]
    entry_files = {h.split(":")[0] for h in entries}
    assert entry_files == {"src\\core\\nids_main.zig"}, (
        f"analyze_packets gained a caller outside nids_main: {entries}"
    )
    # 3. nids_main.main itself is never invoked anywhere in src/.
    mains = [h for h in hits(r"nids_main\.main|nids_main import", zig_files, strip="//")]
    assert mains == [], f"orphan nids_main.main became reachable: {mains}"
    # 4. 0.0.0.0 binds live only in nids_analyze.zig (listener + its own
    # allowlist test); wfp_ioctl.zig only asserts a formatted "0.0.0.0".
    bind_files = {h.split(":")[0] for h in hits(r'"0\.0\.0\.0"', zig_files, strip="//")}
    assert bind_files <= {"src\\core\\nids_analyze.zig", "src\\policy\\wfp_ioctl.zig"}, (
        f"new 0.0.0.0 surface outside the orphan listener: {sorted(bind_files)}"
    )
    # 5. Production daemon never imports the legacy chain; build.zig never
    # builds nids_main as an executable.
    for root in ("src/main.zig", "src/daemon.zig"):
        lines = code_lines(REPO / root, "//")
        bad = [f"{root}:{i}:{line.strip()[:100]}" for i, line in lines
               if re.search(r"nids_main|windows_capture|core/nids_analyze\.zig", line)]
        assert bad == [], f"production daemon imports legacy TCP chain: {bad}"
    build = (REPO / "build.zig").read_text(encoding="utf-8")
    assert "nids_main" not in build, "build.zig must never build the orphan nids_main entry"
