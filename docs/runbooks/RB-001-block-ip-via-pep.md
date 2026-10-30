# RB-001: Block IP via PEP

> **HISTORICAL/LAB REFERENCE — NOT FOR PRODUCTION.** AEGIS is a
> detection-only Kernel NIDS; production host enforcement is out of scope.

## Objective

Respond to a confirmed-malicious source IP through the PEP-gated block
flow. On this production host the gate is closed, so a block is
REFUSED by design -- this runbook proves the refusal path too. Any positive
host-effect material below is historical/lab evidence, not a product roadmap.

## Prerequisites

- System running; operator shell in `D:\NIDs_Windows`.
- Confirmed-malicious IP (detection evidence, not a hunch).

## Steps

1. **Verify the threat (read-only)**
   ```bat
   python tools\aegisctl.py events tail --count 20
   python tools\aegisctl.py forensic search --field src_ip --value <ip>
   ```
   - Proceed only on a matching record with severity high/critical.

2. **Attempt the block (PEP-gated)**
   ```bat
   python tools\aegisctl.py block add --ip <ip> --reason "<why>"
   ```
   - Production (gate closed): expect a structured refusal, exit
     nonzero, NO host effect. That refusal IS the correct outcome --
     record it.
   - Lab with an open gate: expect a validated receipt; without one,
     treat any success claim as false.

3. **Verify enforcement state (never trust the request alone)**
   ```bat
   python tools\aegisctl.py block list
   python tools\aegisctl.py enforce status
   ```
   - A real block needs `BLOCKED_CONFIRMED` + receipt fields
     (filter/request ids, provider). Anything less is PEP_UNVERIFIED.
   - Do NOT use the retired `scripts/aegis_block.py` (direct UDP flow
     bypasses the receipt postcondition -- quarantined).

4. **Monitor**
   - `events tail` for continued attempts from the IP; closed gate =
     detections only, no drops claimed.

## Verification

- Refusal on prod: nonzero exit + reason naming the closed gate.
- Lab success: `block list` shows the IP AND `enforce status` shows a
  receipt-backed confirmation.
- Forensic ring shows the attempt record either way.

## Rollback

```bat
python tools\aegisctl.py block remove --ip <ip>
python tools\aegisctl.py block list
```
Second command must no longer show the IP.

## Notes

- WFP provider READY but gate closed is the steady state here.
- Quarantine positive path is a lab proof: RB-013.

## References

- RB-012 (lab block proof), RB-013 (quarantine), WARDEN_CUTOVER_SPEC.md
- EVT-153 (gate closed on prod), EVT-112/113 (quarantine receipts)
