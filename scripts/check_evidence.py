#!/usr/bin/env python3
import json, os

# Check evidence index (UTF-8: entries carry Thai text)
ei = json.load(open('EVIDENCE_INDEX.json', encoding='utf-8'))
print('Evidence entries:', len(ei.get('evidence', [])))
print('Known gaps:', len(ei.get('known_gaps', [])))
print('Level summary:', ei.get('evidence_level_summary', {}))

print('\n---')

# Check forensic provenance (optional file; the index is authoritative)
prov_path = 'src/tests/forensic/provenance.json'
if os.path.exists(prov_path):
    fp = json.load(open(prov_path, encoding='utf-8'))
    print('Forensic provenance keys:', list(fp.keys())[:10])
else:
    print('Forensic provenance: no provenance.json (see EVIDENCE_INDEX evidence entries)')