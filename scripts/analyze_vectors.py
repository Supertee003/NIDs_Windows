#!/usr/bin/env python3
import json, struct, os

gv = json.load(open('tests/contracts/event_vectors/event_vectors/golden_vectors.json'))
vectors = gv.get('vectors', [])

print(f"Total vectors: {len(vectors)}")
print(f"Schema: {gv.get('schema_version')}")
print(f"Wire size: {gv.get('wire_size')}")
print(f"Magic (int): {gv.get('magic')}")

for i, v in enumerate(vectors):
    hex_str = v.get('hex', '')
    data = bytes.fromhex(hex_str.replace(' ', ''))
    
    magic = struct.unpack_from('<I', data, 0)[0]
    version = struct.unpack_from('<H', data, 4)[0]
    struct_size = struct.unpack_from('<H', data, 6)[0]
    event_id = struct.unpack_from('<Q', data, 8)[0]
    timestamp_ms = struct.unpack_from('<Q', data, 16)[0]
    monotonic_ns = struct.unpack_from('<Q', data, 24)[0]
    source = data[32]
    source_ip = struct.unpack_from('<I', data, 33)[0]
    source_port = struct.unpack_from('<H', data, 37)[0]
    dest_ip = struct.unpack_from('<I', data, 39)[0]
    dest_port = struct.unpack_from('<H', data, 43)[0]
    session_id = struct.unpack_from('<Q', data, 45)[0]
    protocol = data[53]
    direction = data[54]
    layer_id = data[55]
    is_pipe = data[56]
    event_type = struct.unpack_from('<I', data, 57)[0]
    severity = data[61]
    rule_id = struct.unpack_from('<I', data, 62)[0]
    ruleset_version = struct.unpack_from('<Q', data, 66)[0]
    payload_length = struct.unpack_from('<I', data, 74)[0]
    payload_hash = struct.unpack_from('<Q', data, 78)[0]
    policy_action = data[86]
    enforcement_status = data[87]
    defcon_impact = data[88]
    context_flags = struct.unpack_from('<I', data, 89)[0]
    reserved = data[93:109].hex()
    
    print(f"\n--- Vector {i+1} ---")
    print(f"  magic: 0x{magic:08X}")
    print(f"  version: {version}")
    print(f"  struct_size: {struct_size}")
    print(f"  event_id: {event_id}")
    print(f"  timestamp_ms: {timestamp_ms}")
    print(f"  monotonic_ns: {monotonic_ns}")
    print(f"  source: {source}")
    print(f"  source_ip: {source_ip} (0x{source_ip:08X})")
    print(f"  source_port: {source_port}")
    print(f"  dest_ip: {dest_ip} (0x{dest_ip:08X})")
    print(f"  dest_port: {dest_port}")
    print(f"  session_id: {session_id}")
    print(f"  protocol: {protocol} ({'TCP' if protocol==6 else 'UDP' if protocol==17 else 'Other'})")
    print(f"  direction: {direction} (0=inbound, 1=outbound)")
    print(f"  layer_id: {layer_id} ({'TCP' if layer_id==0 else 'WFP' if layer_id==1 else 'kernel' if layer_id==2 else 'pipe' if layer_id==3 else 'Other'})")
    print(f"  is_pipe: {is_pipe}")
    print(f"  event_type: {event_type}")
    print(f"  severity: {severity} (Low={severity==0} Medium={severity==1} High={severity==2} Critical={severity==3})")
    print(f"  rule_id: {rule_id}")
    print(f"  ruleset_version: {ruleset_version}")
    print(f"  payload_length: {payload_length}")
    print(f"  payload_hash: 0x{payload_hash:016X}")
    print(f"  policy_action: {policy_action} (ALLOW={policy_action==0} ALERT={policy_action==1} BLOCK={policy_action==2} QUARANTINE={policy_action==3})")
    print(f"  enforcement_status: {enforcement_status} (pending=0 enforced=1 failed=2 rolled_back=3)")
    print(f"  defcon_impact: {defcon_impact} (1-5, 5=normal)")
    print(f"  context_flags: {context_flags} (bitfield)")
    print(f"  reserved: {reserved}")