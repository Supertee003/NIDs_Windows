#!/usr/bin/env python3
import json, struct, os

gv = json.load(open('tests/contracts/event_vectors/event_vectors/golden_vectors.json'))
vectors = gv.get('vectors', {})

print('Golden vectors count:', len(vectors))
print('Schema version:', gv.get('schema_version'))
print('Wire size:', gv.get('wire_size'))
print('Magic (int):', hex(gv.get('magic')))

fname = list(vectors.keys())[0]
v = vectors[fname]
data = bytes.fromhex(v['hex'].replace(' ', ''))

print(f'\nVector: {fname}')
print('Size:', len(data), 'bytes (expected 109)')
print('Magic:', hex(struct.unpack_from('<I', data, 0)[0]))
print('Version:', struct.unpack_from('<H', data, 4)[0])
print('Struct size:', struct.unpack_from('<H', data, 6)[0])
print('Event ID:', struct.unpack_from('<Q', data, 8)[0])
print('Source:', data[32])

# Protocol
p = data[53]
proto_str = 'TCP' if p==6 else 'UDP' if p==17 else 'Other'
print('Protocol:', proto_str)

# Direction
d = data[54]
dir_str = 'inbound' if d==0 else 'outbound'
print('Direction:', dir_str)

# Layer ID
l = data[55]
if l==0: layer_str = 'TCP'
elif l==1: layer_str = 'WFP'
elif l==2: layer_str = 'kernel'
elif l==3: layer_str = 'pipe'
else: layer_str = 'Other (%d)' % l
print('Layer ID:', layer_str, '(%d)' % l)

# Is pipe
print('Is pipe:', data[56])

# Severity
s = data[61]
sev_str = 'Low' if s==0 else 'Medium' if s==1 else 'High' if s==2 else 'Critical'
print('Severity:', sev_str)

# Policy action
pa = data[86]
pa_str = 'ALLOW' if pa==0 else 'ALERT' if pa==1 else 'BLOCK' if pa==2 else 'QUARANTINE'
print('Policy action:', pa_str)

# DEFCON impact
di = data[88]
print('DEFCON impact:', di, '(1-5)')

# Reserved
res = data[93:109].hex()
print('Reserved (bytes 93-108):', res)
PYEOF