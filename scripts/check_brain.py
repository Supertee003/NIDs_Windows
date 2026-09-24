import json

d = json.load(open('EVIDENCE_INDEX.json'))
entries = d.get('evidence', [])
brain_entries = [e for e in entries if isinstance(e, dict) and ('PY-001' in e.get('id', '') or 'brain' in e.get('title', '').lower() or 'RAG' in e.get('title', '').upper())]
print(f"Found {len(brain_entries)} brain/RAG evidence entries:")
for e in brain_entries:
    print(f"  {e['id']}: {e['title'][:70]} ... level={e['level']}")