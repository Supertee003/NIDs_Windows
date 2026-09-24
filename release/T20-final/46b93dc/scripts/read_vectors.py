#!/usr/bin/env python3
import json, os
base = r'tests/contracts/event_vectors'
meta_path = os.path.join(base, 'vectors_metadata.json')
print('Looking for:', meta_path)
print('Exists:', os.path.exists(meta_path))
if os.path.exists(meta_path):
    m = json.load(open(meta_path))
    print('Total vectors:', m.get('total_vectors', len(m.get('vectors', []))))
    for v in m.get('vectors', [])[:5]:
        vid = v.get('id', '?')
        sz = v.get('size', '?')
        desc = v.get('description', '')[:80]
        fields = v.get('fields', '?')
        print(f'Vector {vid}: size={sz}, desc={desc}, fields={fields}')
else:
    print('Metadata not found')
PYEOF