# AEGIS Brain Cython Module - Build Instructions (Phase 17)

## Prerequisites

```bash
pip install cython setuptools
# On Windows, also need Visual C++ Build Tools
```

## Build

```bash
cd brain/aegis_brain_cython
python setup.py build_ext --inplace
```

This creates `fast_scan.pyd` (Windows) or `fast_scan.so` (Linux).

## Verify

```bash
python -c "from brain.aegis_brain_cython.bridge import is_available; print(f'Cython: {is_available()}')"
```

## Integration

In `brain/windows_brain.py`, replace:

```python
# Old (pure Python):
def run_regex_scan(payload, tier2_engine, rules_data):
    safe_payload = str(payload)[:MAX_PAYLOAD_SIZE]
    for r in rules_data.get("nids_rules", []):
        ...

# New (with Cython acceleration):
from aegis_brain_cython.bridge import scan_payload, get_severity

def run_regex_scan(payload, tier2_engine, rules_data):
    safe_payload = bytes(str(payload)[:MAX_PAYLOAD_SIZE], 'utf-8')
    patterns = [r.get('fast_pattern', '').encode('utf-8')
                for r in rules_data.get('nids_rules', [])]
    idx, matched = scan_payload(safe_payload, patterns)
    if idx >= 0:
        rules = rules_data.get('nids_rules', [])
        r = rules[idx]
        return (r.get('name', ''), r.get('action', 'Alert').upper(),
                r.get('rule_id', 'UNKNOWN'),
                get_severity(r.get('severity', 'Medium')))
    return None
```

## Performance

Expected speedup: **3-5x** for payload scanning, **1.5-2x** for DEFCON calculation.

Benchmark:
```bash
python -c "from brain.aegis_brain_cython.fast_scan import benchmark_scan; benchmark_scan()"
```
