# QUARANTINED (LEGACY-INERT-001): retained for history only.
# Nothing in the runtime imports this file and the installer does not ship it.
# Several of these scripts rewrite tracked files when run (for example
# tools/aegisctl/commands/console.py or AUTHORITY_MAP.json), so an accidental
# `python tools/legacy/<name>.py` was a tree mutation. The guard below makes the
# file inert: it exits before any line of the original body executes.
raise SystemExit(
    "QUARANTINED: tools/legacy/fix_forensics_parser.py must not run; retained for history only."
)

from pathlib import Path
import re

path = Path('tools/aegisctl.py')
text = path.read_text(encoding='utf-8-sig')

pattern = re.compile(
    r'(?ms)^    forensic = sub\.add_parser\("forensics",.*?^    rules = sub\.add_parser\("rules",'
)
replacement = '''    forensic = sub.add_parser("forensics", help="Inspect forensic records and hash chain")
    forensic_sub = forensic.add_subparsers(dest="forensics_command")
    flist = forensic_sub.add_parser("list", help="List forensic records")
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
    fverify = forensic_sub.add_parser("verify", help="Verify forensic hash chain")
    fverify.add_argument("--json", action="store_true",
                         help="Emit machine-readable JSON")
    forensic.set_defaults(forensics_command="list", func=cmd_forensics)
    rules = sub.add_parser("rules",'''

match = pattern.search(text)
if not match:
    raise SystemExit('FORENSICS_PARSER_BLOCK_NOT_FOUND')

text = text[:match.start()] + replacement + text[match.end():]
path.write_text(text, encoding='utf-8', newline='')
print('FIX_OK: forensics parser indentation normalized')
