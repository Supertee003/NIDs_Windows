#!/usr/bin/env python3
import json

with open('evidence_index.json', 'r') as f:
    d = json.load(f)

summary = d['evidence_level_summary']
print('Evidence level summary:')
for k in summary:
    print(f'  {k}: {summary[k]}')

print()
print('Known gaps:')
for g in d.get('known_gaps', []):
    print(f'  {g["id"]}: {g["title"]} (severity: {g["severity"]}, status: {g["status"]})')