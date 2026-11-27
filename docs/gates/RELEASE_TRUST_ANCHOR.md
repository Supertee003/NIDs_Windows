# Release trust anchor (owner approval)

The `release_signature` gate has two independent checks
(`tools/final_audit.py::verify_detached_signature`): the detached Ed25519
signature must verify over the `SHA256SUMS` bytes, and the signing key must
match an owner-approved anchor supplied as `AEGIS_RELEASE_TRUSTED_PUBLIC_KEY`.
The second check is what separates "cryptographically signed" from "signed by
the release key", and it is deliberately fail-closed: no anchor, no pass.

## Approved anchors

Two owner-approved Ed25519 anchors are recorded. Only **public** keys appear
here; private keys never enter the repository.

### Published-release anchor (2026-11-18, immutable identity)

```
txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o=
```

| Field | Value |
|---|---|
| Algorithm | Ed25519, raw 32-byte public key, base64 |
| Approved by | owner (Supertee003), 2026-11-18 |
| Private key custody | local only, `.keys/aegis-release.ed25519` (git-ignored, never committed) |
| First release signed with this key | `release/T20-final/ad7948c` |
| Historical candidates (superseded) | `7d91e30` (superseded), `bece8f1` (rejected: unsigned drivers), `b597e71` (superseded by `466a226`) — do NOT verify these as current |
| Published candidate signed with this key | `release/T20-final/466a226` (v1.1, build source `a53eda8`) |

This key already signed `ad7948c`, so approving it preserved continuity. The
published `v1.1` / `466a226` / `a53eda8` identity is **not** rewritten by the
record below.

### Current-source anchor (2026-11-26, additive)

The owner explicitly approved generating a **new** Ed25519 key for the current
build source `aa3b7b0`, because the old release record predates that source and
cannot satisfy `commit_contains_runtime`. This is an additional trust anchor,
not a rewrite of history.

```
DCNPphsqfklICz6MxxfS5jP005BOOGbug8Vxgpn8cZU=
```

| Field | Value |
|---|---|
| Algorithm | Ed25519, raw 32-byte public key, base64 |
| Approved by | owner, 2026-11-26 |
| Private key custody | `D:\aegis-tmp\keys\aegis-release-aa3b7b0.ed25519` (outside the tracked tree, owner-held, never committed) |
| Current candidate signed with this key | `release/T20-final/6c94b47` (digest `94F65BCC7B6D4E9C1CA977D1D74BAE4DCACD85CD4698754FEB3F1985EA15B1AE`) |
| Scope | release-record verification only; not E5/E6/E7 qualification |

Full record: `analysis/current-head/RELEASE-SIGNATURE-AA3B7B0-20261126.md`.

### Owner-delegated current-source signature (2026-11-28)

The owner explicitly authorized the agent to complete the owner-only
`release_signature` work while keeping soak last. The same approved key signed a
new additional candidate tree; no new key was generated and the published
`v1.1` identity was not changed.

| Field | Value |
|---|---|
| Signed tree | `release/T20-final/128c7f5` (270 assembled files, 206 tracked, 241 SHA-256 artifact lines) |
| Signed records commit | `128c7f5` (contains build source `c01e809`) |
| `signed_digest` | `EBE91BB403BFF2488E87A9F7A2E9D78AC566B612197DBE0DFF921196FCB32501` |
| Private key custody | `D:\aegis-tmp\keys\aegis-release-aa3b7b0.ed25519` (outside the tree, never committed) |
| Gate result | `release_signature` PASS with owner anchor; board 5/6, `soak_24h` still OPEN |
| Scope | release-record verification only; not E5/E6/E7, not driver signing, not a soak PASS |

Full record: `analysis/current-head/RELEASE-SIGNATURE-C01E809-20261128.md`.

### Owner-delegated records-tip attestation (2026-11-28)

The owner explicitly authorized signing on their behalf. The same approved key
signed `analysis/current-head/owner-key-attestation-aa3b7b0-20261128/SHA256SUMS`
over `CURRENT-SOURCE-IDENTITY.txt` (`signed_digest`
`A810F023E18714273524A5D3D0FDAB4D22D1D1F9901AF360C5A8B6F5DF67E314`,
`sign_release.py --verify` PASS). This is an **integrity attestation of the
honest records tip**, not a new release, not E7, not a signed-driver claim, and
it does not close `soak_24h`. It lives under `analysis/`, so the release gate's
signature scan is unchanged. Record:
`analysis/current-head/OWNER-KEY-ATTESTATION-AA3B7B0-20261128.md`.

## Operator use

```powershell
# Published v1.1 record (unchanged)
$env:AEGIS_RELEASE_TRUSTED_PUBLIC_KEY = 'txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o='
python tools\sign_release.py --verify --dir release\T20-final\466a226

# Current-source record (historical at c01e809)
$env:AEGIS_RELEASE_TRUSTED_PUBLIC_KEY = 'DCNPphsqfklICz6MxxfS5jP005BOOGbug8Vxgpn8cZU='
python tools\sign_release.py --verify --dir release\T20-final\6c94b47
python tools\final_audit.py --release-check

# Owner-delegated current-source record for build source c01e809
python tools\sign_release.py --verify --dir release\T20-final\128c7f5
```

Use the record matching the build source you are auditing. `sign_release.py
--verify` checks the signature only; `final_audit.py --release-check` is the
gate that also demands the owner anchor, the signed commit to be in HEAD's
history, and that commit to contain the shipped runtime commit. The newest
complete signature (`128c7f5` for build source `c01e809`) is the one judged by
the gate. `release_signature` PASS does not close `soak_24h`; the board remains
NOT SHIPPABLE until a fresh 24 h window is evaluated.

## Rotation

If this key is ever lost or compromised: generate a new one with
`python tools\sign_release.py --generate-key .keys/aegis-release.ed25519`,
record the new public key here in a commit that also re-signs the candidate,
and update CI. The old key keeps verifying old trees — signatures do not
expire — so rotation is a forward operation, not a rewrite.