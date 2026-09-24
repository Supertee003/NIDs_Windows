#!/usr/bin/env python3
import json, re, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
RULES=ROOT/'configs/Rules.json'; MANIFEST=ROOT/'analysis/RULE_22_DETECTION_FIXTURE_MANIFEST.json'
OUT=ROOT/'analysis/RULE_22_OBSERVE_ONLY_MATCHING.json'; MD=ROOT/'analysis/RULE_22_OBSERVE_ONLY_MATCHING.md'
def main():
    rules=json.loads(RULES.read_text())['nids_rules']; by_id={r['rule_id']:r for r in rules}
    m=json.loads(MANIFEST.read_text()); fs=m['fixtures']
    if m.get('execution_mode')!='synthetic_observe_only' or m.get('global_prevention_gate')!='closed': raise SystemExit('unsafe manifest')
    if len(rules)!=22 or len(fs)!=22: raise SystemExit('expected 22 rules and fixtures')
    rows=[]; failures=[]
    for f in fs:
        rid=f['rule_id']; r=by_id.get(rid); e=f['expected_detection']; sig=f["synthetic_input"]["marker"]+' '+e['match_pattern']+' C:\\Windows\\System32\\drivers\\etc\\hosts'
        try: rx=bool(r and re.search(r['regex_pattern'],sig)); err=None
        except re.error as x: rx=False; err=str(x)
        contract=bool(r and r.get('name')==f.get('name') and r.get('severity')==f.get('severity') and r.get('action')==f.get('configured_action') and r.get('fast_pattern')==e.get('fast_pattern') and r.get('regex_pattern')==e.get('regex_pattern'))
        fast=bool(r and r.get('fast_pattern','') in sig); ok=fast and rx and contract
        if not ok: failures.append(rid)
        rows.append({'rule_id':rid,'layer':r.get('layer') if r else None,'severity':r.get('severity') if r else None,'action':r.get('action') if r else None,'fast_match':fast,'regex_match':rx,'regex_error':err,'contract':contract,'matched':ok,'qualification':'SYNTHETIC_MATCH_ONLY_NOT_SENSOR_PROOF' if ok else 'FAIL','sensor_proof':'not_exercised','host_effect':'none','prevention_gate':'closed','wfp_block_called':False,'enforcement_receipt':False})
    out={'schema':'aegis.rule-matching-observe-only.v1','generated_at_ms':int(time.time()*1000),'mode':'synthetic_observe_only','active':False,'prevention_gate':'closed','rule_count':len(rows),'matched_count':sum(x['matched'] for x in rows),'sensor_proof_count':0,'host_effect_count':0,'failures':failures,'results':rows}
    OUT.write_text(json.dumps(out,indent=2)+'\n'); MD.write_text('# Rules 22 Observe-only Matching\n\nSynthetic matching only; no sensor or enforcement proof.\n')
    print(json.dumps({'passed':not failures,'rule_count':len(rows),'matched_count':out['matched_count'],'sensor_proof_count':0,'host_effect_count':0,'prevention_gate':'closed','failures':failures},indent=2)); return 0 if not failures else 1
if __name__=='__main__': raise SystemExit(main())
