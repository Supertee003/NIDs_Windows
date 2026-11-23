# Security Policy

## Supported status

| Version | Status |
|---|---|
| `v1.1` (published, immutable) | Supported as the current release record |
| `main` development head | Best-effort; current build source `ab0fa17` (audit-close slice). `v1.1` stays immutable |

AEGIS is a **research and development** Windows kernel-assisted NIDS. It is released for
development, qualification, and observe-only lab operation. It is **not** an IPS, does not block
or quarantine hosts in production, and is not a replacement for a production enterprise NIDS/EDR.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue:

- Preferred: GitHub **Security → Report a vulnerability** (private advisory) on this repository.
- Alternative: contact the repository owner privately via GitHub.

Include:

- affected commit or release,
- component (Zig runtime, Go Nose, WFP adapter, Rust PEP, Python tooling, IPC, release assets),
- reproduction steps on an authorized lab host,
- impact and any suggested mitigation.

Do not publish exploit details, attack payloads, or private host artifacts before the issue has been
reviewed. Do not run experimental kernel drivers on production systems.

## Scope and exclusions

**In scope:** detection bypass in the observe-only pipeline, IPC authorization issues, unsafe event
parsing, forensic integrity weaknesses, release verification problems, privilege-boundary mistakes.

**Out of scope:** host-effect enablement, WFP mutation, Signed-IR promotion, EV/HLK driver signing,
and Microsoft attestation. These are deliberately outside the product scope and are not "pending
features" (see `README.md` and `AUTHORITY_MAP.json`).

## Security model in one paragraph

Zig is the single runtime owner. Go Nose and the C/C++ adapters are acquisition spokes, Rust is a
detection-only policy/evidence authority with **no host-effect authority**, Python is analytics and
tooling, and TypeScript authors policy artifacts. Production stops at the policy decision: findings
become hash-chained forensic evidence and an IDS evidence receipt. A `BLOCK` label is an intent,
never proof of a host effect. See `docs/architecture/SECURITY_BOUNDARIES.md` and
`docs/SECURITY_THREAT_MODEL.md`.
