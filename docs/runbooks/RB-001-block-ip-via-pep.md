# RB-001: Block IP via PEP

## Objective
Manually block a source IP address using the Policy Enforcement Point (PEP). This runbook covers the incident response procedure for blocking malicious traffic.

## Prerequisites
- AEGIS NIDS running with PEP initialized
- Operator access to the Mouth (DEFCON TUI) or API
- Confirmed malicious source IP from detection or threat intel

## Steps

1. **Verify the threat**
   - Check detection evidence in forensic log:
     ```
     query ForensicLog by src_ip=<malicious_ip>
     ```
   - Confirm verdict is "malicious" with severity >= "high"

2. **Issue block command via PEP**
   - Through Mouth TUI: select "Manual Block IP" action
   - Through API: call `pep_enforcement.block_ip(ip)`
   - The PEP will:
     - Validate the decision (event_id, source_ip non-zero)
     - Execute the block action
     - Return EnforcementResult with status=executed

3. **Verify enforcement**
   - Check PEP result: `status == .executed`, `blocked_ip == <malicious_ip>`
   - Verify IP appears in blocked list: `wfp_ioctl.is_blocked(ip)`

4. **Record in audit trail**
   - Audit trail automatically records: action=manual_block_ip, operator_id=<you>, target=<ip>
   - Verify audit record created: `audit_trail.getById(record_id)`

5. **Monitor for effectiveness**
   - Watch telemetry for blocked traffic attempts
   - Check if source IP continues to attempt connections (should be dropped)

## Verification
- PEP returns `EnforcementResult{ status = .executed, blocked_ip = <ip> }`
- Audit trail contains record with `action = .manual_block_ip`
- Forensic log shows the block action was recorded

## Rollback
To unblock the IP:
1. Issue unblock command: `pep_enforcement.unblock_ip(ip)`
2. Verify `wfp_ioctl.is_blocked(ip) == false`
3. Audit trail records the unblock action automatically

## Notes
- PEP quarantine action is currently DEFERRED (see `docs/PEP_QUARANTINE_STATUS.md`)
- WFP IOCTL is in tracking-only mode (see `docs/WFP_IOCTL_STATUS.md`)
- Block action is recorded even if kernel enforcement is not active

## References
- G10: `core/pep_enforcement_proof.zig` - PEP enforcement proof
- G14: `core/audit_trail_proof.zig` - Audit trail
- G11: `core/forensic_replay_proof.zig` - Forensic query
