"""E5-C-1: diff the export tables of deployed vs new runtime DLLs.

Prints the missing entry points that make the new daemon exit with 0xC0000139
(STATUS_ENTRYPOINT_NOT_FOUND) when staged next to the old DLL set.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

NEW = Path("zig-out/bin")
OLD = Path(r"C:\Program Files\AEGIS NIDS\runtime")
TMP = Path("admin-evidence/e5-host-proof-20261026")
OUT = TMP / "e5c-pe-export-diff.txt"


def exports(path: Path) -> dict[str, int | None]:
    data = path.read_bytes()
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe_off:pe_off + 4] == b"PE\0\0", "not PE"
    coff = pe_off + 4
    opt = coff + 20  # optional header immediately follows the fixed COFF header
    magic = struct.unpack_from("<H", data, opt)[0]
    dd_off = opt + (112 if magic == 0x20B else 96)
    exp_rva, exp_size = struct.unpack_from("<II", data, dd_off)
    if exp_rva == 0:
        return {}
    rva_map = []
    num_sec = struct.unpack_from("<H", data, coff + 2)[0]
    sec_off = opt + struct.unpack_from("<H", data, coff + 16)[0]
    for i in range(num_sec):
        b = sec_off + i * 40
        rva_map.append((struct.unpack_from("<I", data, b + 12)[0],
                        struct.unpack_from("<I", data, b + 8)[0],
                        struct.unpack_from("<I", data, b + 20)[0]))

    def rva2off(rva: int) -> int:
        for v, sz, raw in rva_map:
            if v <= rva < v + sz:
                return rva - v + raw
        raise ValueError(f"rva {rva:#x} unmapped")

    o = rva2off(exp_rva)
    n_funcs, n_names = struct.unpack_from("<II", data, o + 0x14)
    n_ord = struct.unpack_from("<I", data, o + 0x2C)[0]
    aorf = struct.unpack_from("<I", data, o + 0x28)[0]
    if n_ord:
        ord_base = struct.unpack_from("<H", data, rva2off(n_ord))[0]
    else:
        ord_base = 1
    names_rva = struct.unpack_from("<I", data, o + 0x20)[0]
    out: dict[str, int | None] = {}
    for i in range(n_names):
        p = struct.unpack_from("<I", data, rva2off(names_rva) + i * 4)[0]
        s = rva2off(p)
        end = data.index(b"\0", s)
        name = data[s:end].decode("ascii", "replace")
        out[name] = None
    if n_ord and not out:
        # exports-by-ordinal only
        for i in range(n_funcs):
            out[f"#{ord_base + i}"] = ord_base + i - 0 if aorf else None
    return out


def gate(copylist: list[str]) -> int:
    missing_files: list[str] = []
    for dll in ("aegis_pep.dll", "aegis_wfp_user.dll", "aegis_etw_helper.dll",
                "aegis_fim_helper.dll", "aegis_ipc.dll"):
        try:
            new = exports(Path("zig-out/bin") / dll)
            old = exports(Path(r"C:\Program Files\AEGIS NIDS\runtime") / dll)
        except (OSError, ValueError, AssertionError):
            continue
        if (set(new) - set(old)) and (dll not in copylist):
            missing_files.append(dll)
    if missing_files:
        print(f"GATE-FAIL {','.join(missing_files)}")
        return 1
    print("GATE-PASS")
    return 0


def main() -> int:
    lines: list[str] = []
    for dll in ("aegis_pep.dll", "aegis_wfp_user.dll", "aegis_etw_helper.dll",
                "aegis_fim_helper.dll", "aegis_ipc.dll"):
        try:
            new = exports(NEW / dll)
            old = exports(OLD / dll)
        except (OSError, ValueError, AssertionError) as exc:
            lines.append(f"{dll}: SKIP ({exc})")
            continue
        missing = sorted(set(new) - set(old))
        extra = sorted(set(old) - set(new))
        lines.append(f"{dll}: new={len(new)} old={len(old)} missing_in_old={missing} only_in_old={extra}")
        for m in missing:
            lines.append(f"    NEEDS-BUT-OLD-LACKS: {m}")
    text = "\n".join(lines)
    (TMP / "e5c-pe-export-diff.txt").write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--gate":
        sys.exit(gate(sys.argv[2:] if len(sys.argv) > 2 else []))
    sys.exit(main())
