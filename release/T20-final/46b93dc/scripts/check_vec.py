#!/usr/bin/env python3
import re

# Check Go canonical event
data = open('nose/canonical.go', 'r').read()
for m in re.finditer(r'func \(e \*CanonicalEvent\) (Serialize|Deserialize)', data):
    print(f"Go: {m.group(1)}")

# Check Zig canonical event
data = open('src/contract/canonical_event.zig', 'r').read()
for m in re.finditer(r'(serializeToBytes|deserializeFromBytes)', data):
    print(f"Zig: {m.group(1)}")

# Check C++ adapter
data = open('bridge/aegis_adapter.cpp', 'r').read()
for m in re.finditer(r'kWireSize|memcpy|109', data):
    print(f"C++: {m.group(0)[:30]}")

# Check Python codec
data = open('shared/wire/wire_codec.py', 'r').read()
for m in re.finditer(r'struct\.pack|kWireSize', data):
    print(f"Python: {m.group(0)[:30]}")