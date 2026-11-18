# Elevated plan-S6 WFP cleanup (one shot, receipts printed).
# Deletes ONLY the approved stale set:
#   - AEGIS_BLOCK_10.0.0.99 (remote 10.0.0.99, Tier-2 R0056 artifacts)
#   - filterId 7088032 (stale proof-era id from the S6 list)
#   - name "AEGIS WFP TCP Port Proof Filter" (old-era litter, unique keys;
#     the live static-key proof filter is NOT matched by name+remote and,
#     if present, is left for its owner's unblock path)
# Everything else is listed, never touched. Deletion is by filterKey via
# FWPM (the driver's unblock only handles driver-owned filters).
import ctypes
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from ctypes import wintypes

TARGET_REMOTES = {"10.0.0.99"}
TARGET_IDS = {"7088032"}
TARGET_NAMES = {"AEGIS WFP TCP Port Proof Filter"}


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8)]


def guid_from(s):
    s = s.strip().strip("{}")
    parts = s.split("-")
    d4 = bytes.fromhex(parts[3] + parts[4])
    return GUID(int(parts[0], 16), int(parts[1], 16), int(parts[2], 16),
                (wintypes.BYTE * 8)(*d4))


def cond_texts(item):
    out = set()
    for fc in item.iter("filterCondition"):
        for v in fc.iter():
            if v.tag in ("uint32", "uint16", "uint8", "uint64",
                         "valueLow", "valueHigh") and (v.text or "").strip():
                out.add(v.text.strip())
    return out


xml_path = os.path.join(tempfile.gettempdir(), "wfp.xml")
print("dumping filters...")
r = subprocess.run(["netsh", "wfp", "show", "filters", f"file={xml_path}"],
                   capture_output=True, text=True, timeout=180)
print("netsh rc:", r.returncode)
if r.returncode != 0:
    sys.exit("netsh dump needs an elevated shell")
root = ET.parse(xml_path).getroot()
filters = root.find("filters")
items = filters.findall("item") if filters is not None else []
print("filter items:", len(items))
doomed = []
for it in items:
    nm = it.find("displayData/name")
    name = (nm.text or "").strip() if nm is not None else "?"
    fid = it.find("filterId")
    fidt = fid.text.strip() if fid is not None and fid.text else ""
    key = it.find("filterKey")
    keyt = key.text.strip() if key is not None and key.text else ""
    texts = cond_texts(it)
    why = None
    if texts & TARGET_REMOTES:
        why = f"remote {sorted(texts & TARGET_REMOTES)}"
    elif fidt in TARGET_IDS:
        why = "S6-listed id"
    elif name in TARGET_NAMES:
        why = "stale proof-era name"
    if why:
        print(f"  STALE id={fidt} name={name} ({why})")
        if keyt:
            doomed.append((fidt, keyt))
print("targets to remove:", len(doomed))

fwpuclnt = ctypes.WinDLL("fwpuclnt.dll")
fwpuclnt.FwpmEngineOpen0.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                     wintypes.LPVOID, wintypes.LPVOID,
                                     ctypes.POINTER(wintypes.HANDLE)]
fwpuclnt.FwpmEngineOpen0.restype = wintypes.DWORD
fwpuclnt.FwpmFilterDeleteByKey0.argtypes = [wintypes.HANDLE,
                                            ctypes.POINTER(GUID)]
fwpuclnt.FwpmFilterDeleteByKey0.restype = wintypes.DWORD
fwpuclnt.FwpmEngineClose0.argtypes = [wintypes.HANDLE]
h = wintypes.HANDLE()
rc = fwpuclnt.FwpmEngineOpen0(None, 10, None, None, ctypes.byref(h))
print("engine open rc:", rc)
if rc == 0:
    try:
        for fidt, keyt in doomed:
            rc = fwpuclnt.FwpmFilterDeleteByKey0(
                h, ctypes.byref(guid_from(keyt)))
            print(f"delete id {fidt}: rc={rc} (0=gone)")
    finally:
        fwpuclnt.FwpmEngineClose0(h)
print("done")
