import ctypes
import json
import os
from ctypes import wintypes

PIPE = r"\\.\pipe\aegis_control"
k = ctypes.WinDLL("kernel32", use_last_error=True)
k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
k.CreateFileW.restype = wintypes.HANDLE
k.WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
k.WriteFile.restype = wintypes.BOOL
k.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
k.ReadFile.restype = wintypes.BOOL
k.CloseHandle.argtypes = [wintypes.HANDLE]
k.CloseHandle.restype = wintypes.BOOL

invalid = ctypes.c_void_p(-1).value
h = k.CreateFileW(PIPE, 0xC0000000, 0, None, 3, 0, None)
if h == invalid:
    print(json.dumps({"stage": "CreateFileW", "error": ctypes.get_last_error(), "pipe": PIPE}))
    raise SystemExit(1)
try:
    request = json.dumps({"command": "system.health", "payload": {}}, separators=(",", ":")).encode()
    sent = wintypes.DWORD()
    ok = k.WriteFile(h, ctypes.create_string_buffer(request), len(request), ctypes.byref(sent), None)
    if not ok:
        print(json.dumps({"stage": "WriteFile", "error": ctypes.get_last_error(), "sent": sent.value}))
        raise SystemExit(2)
    print(json.dumps({"stage": "WriteFile", "sent": sent.value}))
    chunks = []
    for _ in range(4):
        buf = ctypes.create_string_buffer(65536)
        got = wintypes.DWORD()
        ok = k.ReadFile(h, buf, 65535, ctypes.byref(got), None)
        err = ctypes.get_last_error() if not ok else 0
        if got.value:
            chunks.append(buf.raw[:got.value])
        print(json.dumps({"stage": "ReadFile", "ok": bool(ok), "bytes": got.value, "error": err}))
        if ok or err == 109:
            break
        if err != 234:
            break
    raw = b"".join(chunks)
    print(raw.decode("utf-8", errors="replace"))
finally:
    k.CloseHandle(h)
