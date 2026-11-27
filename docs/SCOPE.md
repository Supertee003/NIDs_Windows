# AEGIS v1.1 — canonical scope lock

**STATUS:** canonical scope for the product name, README, runtime, capability
manifest, operations guide, demo and release notes. This page is a **scope
decision record, not new evidence**. It changes no gate, verdict, evidence level,
authority, signature or source file.

> Always read the current status from [`release/release-status.json`](../release/release-status.json).
> Do not treat `v1.1`, `6/6`, `5/6` or any gate count as an automatically current
> value: verify the Git tag and the release manifest first. The published release
> identity is immutable; the current build source is a **different** board.

## 1. Product identity

**AEGIS Kernel NIDS**

A Windows-native Network Intrusion Detection System that uses kernel-assisted
telemetry and user-mode processing to collect, analyze and store evidence of
security-relevant events.

- **Operational mode:** Detection-only / Observe-only.
- **Host enforcement:** disabled (`prevention_gate=closed`, `host_effect_capable=false`).
- **Policy evaluation:** Rust PEP produces detection evidence; it has no host-effect authority.

## 2. Release scope

In scope for `v1.1`:

- Development.
- Qualification.
- Observe-only evaluation.

Explicitly **out of scope** for this release:

- Production fleet deployment before qualification.
- Automatic network blocking.
- Process termination.
- Host isolation.
- Any claim that the product is an IPS.

This release does **not** provide an authorized production prevention or IPS
capability. Historical lab enforcement material is retained as historical or
lab evidence only; it does not describe production behavior.

## 3. Status vocabulary (anti-ambiguity)

| Term | Meaning | Current value |
|---|---|---|
| Published release identity | Immutable `v1.1` / signed candidate `466a226` / build source `a53eda8` | SHIPPABLE, 6/6 gates PASS, `open=0` — **HISTORICAL relative to current source** |
| Current build source | `aa3b7b0161e425e54155d5767737bffcde7939b5` | **5/6 PASS, `soak_24h` OPEN, NOT SHIPPABLE** |
| Product scope | Detection-only / Observe-only | unchanged by either board |

`open=0` on the published release means zero gates remain open; it does **not**
mean zero gates passed. Never quote one board's numbers under the other board's
label.

## 4. Surfaces bound by this scope

Every surface below must use this page as the scope source and
`release/release-status.json` as the status source:

- `README.md`
- Runtime / capability manifest (`AUTHORITY_MAP.json`, `RUNTIME_CONTRACT.md`)
- Operations guide (`docs/operations/QUICK_START.md`)
- Demo (`docs/portfolio/DEMO.md`)
- Release notes / release board (`release/release-status.json`, `docs/gates/PRODUCTION_READINESS.md`)
- Verification summary (`docs/portfolio/VERIFICATION_SUMMARY.md`)

A feature or document that conflicts with §1–§2 is out of scope until an owner
decision amends **this** page first.

## 5. Boundary to source work

Adding a feature, relaxing a gate, or enabling a host effect is a separate
`SOURCE_PATHS` patch transaction under `AGENTS.md`; it is not a documentation
edit and is not authorized by this scope lock. Source-level claims must still
carry their own build, test and host evidence.
