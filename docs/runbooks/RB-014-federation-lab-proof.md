# RB-014: Federation Live Cluster Verification (Lab)

> Lab network only (host-only). No host effects are involved —
> federation is detection-reporting and outbound-only — but member
> identities and TLS material must still be lab-generated, never
> production credentials.

## Objective

Prove a live multi-node cluster: standalone baseline -> 2-node
formation -> member status -> detection-report flow -> teardown back
to standalone. Each phase names the exact status document that proves
it; anything else is not proof.

## Prerequisites

- Two lab VMs (or one VM + the operator host) with the AEGIS service
  installed. Clocks roughly synchronized (report correlation).
- Lab-generated TLS material (self-signed CA + node certs/keys) if TLS
  is exercised; plaintext TCP is acceptable for formation proof only
  and must be labeled as such.
- `configs/cluster.json` is gitignored by design — cluster membership
  is deployment state, never committed.

## Steps

1. **Standalone baseline** (both nodes, before any config):
   ```
   python tools/aegisctl.py federation
   ```
   Require EXACTLY:
   `{"mode":"standalone","cluster_enabled":false,"nodes":0,"role":"standalone"}`.
   Anything else means leftover state — resolve before proceeding.

2. **Write cluster configs** (both nodes, same member list):
   ```json
   {
     "version": 1,
     "nodes": [
       {"id": "lab-1", "addr": "192.168.56.11", "port": 9001, "name": "lab-1"},
       {"id": "lab-2", "addr": "192.168.56.12", "port": 9001, "name": "lab-2"}
     ]
   }
   ```
   Save as `configs/cluster.json` on each node (see
   `configs/cluster.example.json` for the schema). Use the lab subnet;
   TEST-NET documentation ranges are for targets, not member addrs.

3. **Enable the uplink** (both nodes, service environment):
   ```
   AEGIS_CLUSTER=1
   AEGIS_CLUSTER_NODE_ID=<lab-1|lab-2>
   AEGIS_CLUSTER_HOST=<own addr>
   AEGIS_CLUSTER_PORT=9001
   ```
   Plus TLS material variables (`AEGIS_CLUSTER_SERVER_NAME/ROOTS/
   CHAIN/KEY`) when exercising TLS. Restart the service on both nodes.

4. **Formation proof** (both nodes):
   ```
   python tools/aegisctl.py federation
   ```
   Require: `"mode":"cluster"`, `"cluster_enabled":true`,
   `"role":"member"`, `"nodes":2`, `"connected":1` (each node sees its
   peer). `connected:0` with `nodes:2` means configured but not joined —
   check ports/firewall/TLS names, not the daemon.

5. **Report-flow proof**: generate fixture traffic on lab-1
   (`scripts/aegis_event_gen.py --pipe --fixture xss`), then confirm
   lab-2's federated counters move (`published` up on lab-1,
   received/incident view on lab-2 per the status document fields
   `published/dropped`). Detection stays local on each node —
   federation carries reports, never enforcement orders.

6. **Teardown**: stop the uplink (unset `AEGIS_CLUSTER`, restart both),
   delete `configs/cluster.json`, confirm both nodes return to the
   exact standalone document from step 1.

## Verification

- Step 1 and 6 documents byte-comparable in the fields that matter
  (mode/role/nodes).
- Step 4 shows 2/2 members mutually connected.
- Step 5 moves counters on both sides from a controlled fixture.

## Rollback

Teardown (step 6) IS the rollback — federation has no host effects to
undo. Remove lab TLS material with the VMs if they are disposable.

## Notes

- Enforcement stays local per design (ADR-0007 P4): no federated node
  can order a block on another. Do not test for it; test that a
  foreign order is refused if the surface ever exists.
- Static `configs/cluster.json` discovery has a recorded header-vs-
  parser gap (ADR-0007); if the daemon ignores the file, stop and file
  the exact log lines — do not work around with ad-hoc wiring.
- Single-node "cluster of one" proves nothing; minimum is two members.

## References

- Command + handler: `src/control/protocol.zig` (federation.status),
  `src/control/handler_registry.zig` (statusJson truth table).
- Uplink + discovery: `src/federation/cluster_uplink.zig`,
  `src/federation/node_registry.zig`, `docs/adr/0007-federation-cluster-wiring.md`.
- Test configs: `configs/test/federation_*.json`.
