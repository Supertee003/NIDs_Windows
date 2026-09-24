#!/usr/bin/env python3
import json, os

# Check evidence index
ei = json.load(open('EVIDENCE_INDEX.json'))
print('Evidence Index entries:')
for k, v in ei.items():
    print(f'  {k}: status={v.get("status")}, level={v.get("level")}, description={v.get("description", "")[:60]}')

print('\n---')

# Check forensic provenance
fp = json.load(open('src/tests/forensic/provenance.json'))
print('Forensic provenance keys:', list(fp.keys())[:10])
PYEOF