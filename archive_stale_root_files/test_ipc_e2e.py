"""IPC E2E Test"""
import ctypes, os, sys
if hasattr(os, "add_dll_directory"):
    for d in [r"D:\NIDs_Windows\build\Release", r"D:\NIDs_Windows"]:
        if os.path.isdir(d): os.add_dll_directory(d)

try:
    ipc = ctypes.CDLL("aegis_ipc_c.dll")
    print("  IPC C wrapper: LOADED")
except OSError as e:
    print(f"  IPC C wrapper: FAILED - {e}")
    sys.exit(1)

# init
try:
    ipc.aegis_ipc_init.argtypes = [ctypes.c_char_p, ctypes.c_int]
    ipc.aegis_ipc_init.restype = ctypes.c_int
    r = ipc.aegis_ipc_init(b"aegis_test", 5555)
    print(f"  init() = {r}")
except Exception as e:
    print(f"  init() error: {e}")

# status
try:
    ipc.aegis_ipc_status.restype = ctypes.c_int
    s = ipc.aegis_ipc_status()
    backend = "C++ bridge active" if s == 1 else "stub mode"
    print(f"  status() = {s} ({backend})")
except Exception as e:
    print(f"  status() error: {e}")

# send
try:
    ipc.aegis_ipc_send.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    ipc.aegis_ipc_send.restype = ctypes.c_int
    msg = b"ALERT:intrusion_detected"
    sent = ipc.aegis_ipc_send(b"events", msg, len(msg))
    print(f"  send() = {sent} bytes")
except Exception as e:
    print(f"  send() error: {e}")

# get_stats
try:
    ipc.aegis_ipc_get_stats.restype = ctypes.c_int
    stats = ipc.aegis_ipc_get_stats()
    print(f"  get_stats() = {stats}")
except Exception as e:
    print(f"  get_stats() error: {e}")

# shield
try:
    shield = ctypes.CDLL("aegis_shield.dll")
    print("  Shield: LOADED")
except OSError:
    print("  Shield: NOT FOUND")

# cython
try:
    from aegis_shield_cy import AegisShield
    cy = AegisShield()
    print(f"  Cython: {'LOADED' if cy.loaded else 'NOT LOADED'}")
except ImportError as e:
    print(f"  Cython: NOT AVAILABLE ({e})")

print("  IPC: TEST COMPLETE")
