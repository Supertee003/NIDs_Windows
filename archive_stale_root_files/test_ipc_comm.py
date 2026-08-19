"""Test IPC communication between Python Brain and C++ Bridge"""
import ctypes, os, sys, time

# Setup DLL directories
if hasattr(os, 'add_dll_directory'):
    for d in [r"D:\NIDs_Windows\build\Release", r"D:\NIDs_Windows"]:
        if os.path.isdir(d):
            os.add_dll_directory(d)

print("=== IPC Communication Test ===")

# Load IPC C wrapper
try:
    ipc = ctypes.CDLL("aegis_ipc_c.dll")
    print("[1] aegis_ipc_c.dll loaded")
except OSError as e:
    print(f"[1] FAIL: Cannot load IPC DLL: {e}")
    sys.exit(1)

# Test each function
functions = {
    'aegis_ipc_init': {'argtypes': [ctypes.c_char_p, ctypes.c_int], 'restype': ctypes.c_int},
    'aegis_ipc_send': {'argtypes': [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int], 'restype': ctypes.c_int},
    'aegis_ipc_recv': {'argtypes': [ctypes.c_char_p, ctypes.c_int], 'restype': ctypes.c_int},
    'aegis_ipc_status': {'argtypes': [], 'restype': ctypes.c_int},
    'aegis_ipc_shutdown': {'argtypes': [], 'restype': None},
}

print("[2] Testing function signatures...")
for name, spec in functions.items():
    try:
        func = getattr(ipc, name)
        func.argtypes = spec['argtypes']
        func.restype = spec['restype']
        print(f"    + {name} - OK")
    except AttributeError:
        print(f"    - {name} - NOT FOUND")

# Test init
print("[3] Calling aegis_ipc_init...")
try:
    result = ipc.aegis_ipc_init(b"aegis_default", 5555)
    print(f"    init() = {result}")
except Exception as e:
    print(f"    init() error: {e}")

# Test status
print("[4] Calling aegis_ipc_status...")
try:
    status = ipc.aegis_ipc_status()
    print(f"    status() = {status}")
    if status == 1:
        print("    -> IPC backend DLL loaded (C++ bridge active)")
    elif status == 0:
        print("    -> IPC running in stub mode (no C++ backend)")
except Exception as e:
    print(f"    status() error: {e}")

# Test send
print("[5] Calling aegis_ipc_send...")
try:
    test_data = b"ALERT: test intrusion detection event"
    result = ipc.aegis_ipc_send(b"brain_events", test_data, len(test_data))
    print(f"    send() = {result} (bytes sent)")
except Exception as e:
    print(f"    send() error: {e}")

# Test recv
print("[6] Calling aegis_ipc_recv...")
try:
    buf = ctypes.create_string_buffer(4096)
    result = ipc.aegis_ipc_recv(buf, 4096)
    print(f"    recv() = {result} (bytes received)")
    if result > 0:
        print(f"    data: {buf.value[:100]}")
except Exception as e:
    print(f"    recv() error: {e}")

# Test shield
print("[7] Testing aegis_shield.dll...")
try:
    shield = ctypes.CDLL("aegis_shield.dll")
    print("    + aegis_shield.dll loaded")
    # Try scan function
    try:
        scan = shield.aegis_shield_scan
        scan.argtypes = [ctypes.c_char_p, ctypes.c_int]
        scan.restype = ctypes.c_int
        test_pkt = b"GET /admin HTTP/1.1\r\nHost: target\r\n"
        verdict = scan(test_pkt, len(test_pkt))
        print(f"    scan(test_packet) = {verdict}")
    except AttributeError:
        # Try other function names
        for fname in dir(shield):
            if not fname.startswith('_'):
                print(f"    found: {fname}")
except OSError:
    print("    - aegis_shield.dll not found")

# Test Cython wrapper
print("[8] Testing Cython wrapper...")
try:
    from aegis_shield_cy import AegisShield
    cy = AegisShield()
    print(f"    + Cython wrapper loaded: {cy.loaded}")
    if cy.loaded:
        result = cy.scan_packet(b"test packet data")
        print(f"    scan_packet() = {result}")
except ImportError as e:
    print(f"    - Cython wrapper not importable: {e}")
except Exception as e:
    print(f"    - Cython error: {e}")

print("\n=== IPC Test Complete ===")
