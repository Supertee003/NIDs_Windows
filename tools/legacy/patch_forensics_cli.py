from pathlib import Path

path = Path('tools/aegisctl.py')
text = path.read_text(encoding='utf-8-sig')

old_parser = '''    flist = forensic_sub.add_parser("list", help="List forensic records")
    flist.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    flist.add_argument("--source", type=int, help="Filter by EventSource ordinal")
    flist.add_argument("--payload-prefix", help="Filter by exact ASCII payload prefix")
'''
new_parser = '''    flist = forensic_sub.add_parser("list", help="List forensic records")
    flist.add_argument("--limit", type=int, default=100,
                       help="Maximum records to return; capped at 1000")
    flist.add_argument("--after", type=int, default=None,
                       help="Return records with record_seq greater than this value")
    flist.add_argument("--json", action="store_true",
                       help="Emit machine-readable JSON")
    flist.add_argument("--source", type=int,
                       help="Filter by EventSource ordinal")
    flist.add_argument("--payload-prefix",
                       help="Filter by exact ASCII payload prefix")
'''

old_payload = '''    payload = {}
    if getattr(args, "source", None) is not None:
        payload["source"] = args.source
    if getattr(args, "payload_prefix", None):
        payload["payload_prefix"] = args.payload_prefix
    return _print_control_query(command, as_json=getattr(args, "json", True), payload=payload or None)
'''
new_payload = '''    payload = {}
    limit = max(1, min(int(getattr(args, "limit", 100)), 1000))
    payload["limit"] = limit
    if getattr(args, "after", None) is not None:
        payload["after"] = max(0, int(args.after))
    if getattr(args, "source", None) is not None:
        payload["source"] = int(args.source)
    if getattr(args, "payload_prefix", None):
        payload["payload_prefix"] = args.payload_prefix
    return _print_control_query(command, as_json=getattr(args, "json", True), payload=payload)
'''

if old_parser in text:
    text = text.replace(old_parser, new_parser, 1)
elif '--limit", type=int, default=100' not in text:
    raise SystemExit('FORENSICS_LIST_PARSER_NOT_FOUND')

if old_payload in text:
    text = text.replace(old_payload, new_payload, 1)
elif 'payload["limit"] = limit' not in text:
    raise SystemExit('CMD_FORENSICS_PAYLOAD_NOT_FOUND')

path.write_text(text, encoding='utf-8', newline='')
print('PATCH_OK: forensics.list accepts --limit/--after and forwards bounded payload')
