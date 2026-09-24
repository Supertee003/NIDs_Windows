#!/usr/bin/env python3
import json

with open('AUTHORITY_MAP.json', 'r') as f:
    data = json.load(f)

# Update quarantined_duplicates to reflect current state
q = data['quarantined_duplicates']
shield_pep = q[0]

# Update still_bound to reflect current state after our changes
shield_pep['still_bound'] = [
    '# DORMANT: extern "sec_monitor" fn aegis_pep_evaluate removed from policy_contract.zig (PEP-001)',
    '# Tests updated to point at rust-src/lib.rs instead of shield/src/pep.rs',
    '# Shield PEP/WFP exports are quarantined; no active binding exists',
]
shield_pep['exit_criteria_status'] = 'met 3/4: shield exports no PEP symbol, dormant Zig extern removed, T8 expectations point at rust-src/lib.rs'

with open('AUTHORITY_MAP.json', 'w') as f:
    json.dump(data, f, indent=2)

print('Updated AUTHORITY_MAP.json quarantined_duplicates')