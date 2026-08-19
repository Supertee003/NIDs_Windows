#!/usr/bin/env python3
"""bridge_status.py - Write Bridge status to JSON for Nose/Mouth IPC"""
import json, os, time, ctypes, sys
from pathlib import Path
try:
    dll = ctypes.CDLL("dist/aegis_ipc.dll")
    dll.aegis_bridge_init.restype = ctypes.c_int32
    dll.aegis_bridge_get_defcon.restype = ctypes.c_uint8
    dll.aegis_bridge_get_event_count.restype = ctypes.c_uint32
    dll.aegis_bridge_get_dropped_count.restype = ctypes.c_uint32
    AVAILABLE = True
except OSError:
    AVAILABLE = False
ROOT = Path(__file__).resolve().parent.parent
STATUS = ROOT / "logs" / "bridge_status.json"
def write():
    if not AVAILABLE: return
    d = int(dll.aegis_bridge_get_defcon())
    e = int(dll.aegis_bridge_get_event_count())
    dr = int(dll.aegis_bridge_get_dropped_count())
    labels = {1:"MAXIMUM",2:"SEVERE",3:"HIGH",4:"ELEVATED",5:"SAFE"}
    s = {"defcon_level":d,"defcon_label":labels.get(d,"UNKNOWN"),"event_count":e,"dropped_count":dr,"critical_count":0,"blocked_ips":0,"kernel_threats":0,"total_alerts":e,"uptime_ms":int(time.time()*1000)}
    tmp = STATUS.with_suffix('.tmp')
    tmp.write_text(json.dumps(s, indent=2))
    tmp.rename(STATUS)
def main():
    if not AVAILABLE: print("[bridge_status] DLL not found"); sys.exit(0)
    if dll.aegis_bridge_init() != 0: sys.exit(1)
    print("[bridge_status] Writing status...")
    try:
        while True: write(); time.sleep(1.0)
    except KeyboardInterrupt: print("\n[bridge_status] Stopped")
if __name__ == "__main__": main()
