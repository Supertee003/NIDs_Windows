#!/usr/bin/env python3
"""Print exported symbols from a PE/PE+ DLL without dumpbin or LLVM tools."""
from __future__ import annotations

import struct
import sys
from pathlib import Path


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def cstr(data: bytes, off: int) -> str:
    end = data.find(b"\0", off)
    if end < 0:
        end = len(data)
    return data[off:end].decode("ascii", errors="replace")


def main(path: str) -> int:
    data = Path(path).read_bytes()
    if data[:2] != b"MZ":
        raise SystemExit("not a PE file")
    pe = u32(data, 0x3C)
    if data[pe : pe + 4] != b"PE\0\0":
        raise SystemExit("invalid PE signature")

    number_sections = u16(data, pe + 6)
    optional_size = u16(data, pe + 20)
    optional = pe + 24
    magic = u16(data, optional)
    if magic == 0x10B:
        data_dir = optional + 96
    elif magic == 0x20B:
        data_dir = optional + 112
    else:
        raise SystemExit(f"unsupported optional-header magic 0x{magic:X}")

    export_rva = u32(data, data_dir)
    if export_rva == 0:
        print("<no exports>")
        return 0

    section_table = optional + optional_size
    sections = []
    for i in range(number_sections):
        off = section_table + i * 40
        virtual_size = u32(data, off + 8)
        virtual_address = u32(data, off + 12)
        raw_size = u32(data, off + 16)
        raw_ptr = u32(data, off + 20)
        sections.append((virtual_address, max(virtual_size, raw_size), raw_ptr))

    def rva_to_file(rva: int) -> int:
        for va, size, raw in sections:
            if va <= rva < va + size:
                return raw + (rva - va)
        raise SystemExit(f"RVA 0x{rva:X} is outside sections")

    directory = rva_to_file(export_rva)
    ordinal_base = u32(data, directory + 16)
    number_functions = u32(data, directory + 20)
    number_names = u32(data, directory + 24)
    functions_rva = u32(data, directory + 28)
    names_rva = u32(data, directory + 32)
    ordinals_rva = u32(data, directory + 36)

    exports: list[tuple[int, str]] = []
    for i in range(number_names):
        name_rva = u32(data, rva_to_file(names_rva) + i * 4)
        name = cstr(data, rva_to_file(name_rva))
        ordinal_index = u16(data, rva_to_file(ordinals_rva) + i * 2)
        if ordinal_index >= number_functions:
            continue
        exports.append((ordinal_base + ordinal_index, name))

    print(f"file={path}")
    print(f"exports={len(exports)}")
    for ordinal, name in sorted(exports):
        print(f"{ordinal:5d} {name}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} DLL_PATH")
    raise SystemExit(main(sys.argv[1]))
