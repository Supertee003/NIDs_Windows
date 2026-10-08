#!/usr/bin/env python3
"""Validate EVIDENCE_INDEX.json evidence_level_summary against actual entries.

Prints the summary and known gaps, then fails (exit 1) when the recorded
per-level counts disagree with the entries themselves — a stale summary
would under- or over-claim evidence. Reads UTF-8 explicitly (cp1252
default crashed on this file) and tolerates EVT entries inside known_gaps,
which carry no severity/status fields.
"""
import json
import sys
from collections import Counter
from pathlib import Path

INDEX = Path(__file__).resolve().parents[1] / 'EVIDENCE_INDEX.json'


def main() -> int:
    with open(INDEX, 'r', encoding='utf-8') as f:
        d = json.load(f)

    summary = d['evidence_level_summary']
    print('Evidence level summary:')
    for k in summary:
        print(f'  {k}: {summary[k]}')

    actual = Counter(
        e['level']
        for key in ('evidence', 'known_gaps')
        for e in d.get(key, [])
        if e.get('level')
    )
    mismatch = [
        f'{lvl}_count: recorded {summary.get(lvl + "_count")}, actual {actual.get(lvl, 0)}'
        for lvl in ('E0', 'E1', 'E2', 'E3', 'E4', 'E5', 'E6', 'E7')
        if summary.get(lvl + '_count') != actual.get(lvl, 0)
    ]

    print()
    print('Known gaps:')
    for g in d.get('known_gaps', []):
        if g['id'].startswith('GAP-'):
            print(f'  {g["id"]}: {g["title"]} (severity: {g.get("severity")}, status: {g.get("status")})')

    if mismatch:
        print()
        print('SUMMARY MISMATCH:')
        for m in mismatch:
            print(f'  {m}')
        return 1
    print()
    print('SUMMARY_VALID: evidence_level_summary matches actual entry counts')
    return 0


if __name__ == '__main__':
    sys.exit(main())
