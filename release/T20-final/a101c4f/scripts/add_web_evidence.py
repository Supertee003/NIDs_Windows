#!/usr/bin/env python3
"""Add WEB-001 to evidence index."""

import json

with open('evidence_index.json', 'r') as f:
    d = json.load(f)

# Check if web dashboard entry already exists
already_exists = any(e.get('id') == 'WEB-001' for e in d['evidence'])

if not already_exists:
    # Add web dashboard entry at E1 level
    new_entry = {
        "id": "WEB-001",
        "title": "UI-001: Web Dashboard — control_api JSON endpoints",
        "level": "E1",
        "component": "ui",
        "description": "Minimal web dashboard reading from control_api JSON endpoints. CLI, TUI, and Web all read from same control_api truth source. No duplicated business logic. Classification: SUPPORT (optional/release-path).",
        "flow_id": "UI-001",
        "files_changed": ["tools/aegisctl/web_dashboard/app.py"],
        "tests": [
            "Flask app imports successfully",
            "GET /api/status returns JSON with subsystem status",
            "GET / endpoint renders dashboard HTML",
            "All three UIs (CLI/TUI/Web) read from same control_api"
        ],
        "result": "PENDING",
        "finding": "Web dashboard scaffold created; integration test pending"
    }
    d['evidence'].append(new_entry)
    
    # Update summary
    summary_key = 'E1_count'
    d['evidence_level_summary'][summary_key] = d['evidence_level_summary'].get(summary_key, 0) + 1
    
    with open('evidence_index.json', 'w') as f:
        json.dump(d, f, indent=2)
    
    print(f"Added WEB-001 to evidence index. E1 count: {d['evidence_level_summary']['E1_count']}")
else:
    print("WEB-001 already exists in evidence index")