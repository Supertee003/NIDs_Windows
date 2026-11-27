# Owner-key attestation of the current-head records tip — `aa3b7b0`

**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5` (unchanged; records-only)  
**RECORDS TIP AT SIGNING:** `f042f8afe324905b03c3076d63b542b49663c658`  
**SIGNED AT:** `2026-11-28T00:44:42+07:00`  
**AUTHORITY:** owner delegated signing on 2026-11-28 (explicit instruction in conversation). Key custody remains outside the tracked tree at `D:\aegis-tmp\keys\aegis-release-aa3b7b0.ed25519`; **no private key bytes were copied, printed into chat, or committed**.

This is a **cryptographic integrity attestation of the current records tip**, produced with the owner's already-approved current-source Ed25519 key. It is deliberately **not** a new release, not E7, not a signed-driver claim, and not a soak PASS.

## What was actually signed

`tools/sign_release.py --sign` signed the bytes of `analysis/current-head/owner-key-attestation-aa3b7b0-20261128/SHA256SUMS`, which lists the SHA-256 of `CURRENT-SOURCE-IDENTITY.txt`. That identity file states only already-recorded facts: build source, records tip, board `5/6 PASS — soak_24h OPEN — NOT SHIPPABLE`, the two real FAIL finalizers, the pinned runtime hashes, and the unchanged published identity.

| Field | Value |
|---|---|
| `algorithm` | `ed25519` |
| `public_key` | `DCNPphsqfklICz6MxxfS5jP005BOOGbug8Vxgpn8cZU=` (approved current-source anchor) |
| `signed_digest` | `A810F023E18714273524A5D3D0FDAB4D22D1D1F9901AF360C5A8B6F5DF67E314` |
| identity file digest | `591203A8681AF4E2C3D453E15E2853277D7BD5BA210764AF1DFD49A472C7A558` |
| `sign_release.py --verify` | `PASS` (exit 0) |

The public key was derived from the owner-held key and matches the anchor recorded in `docs/gates/RELEASE_TRUST_ANCHOR.md` exactly; no key material enters this record.

## What this does NOT do

- Does **not** create a new release identity. Published `v1.1` / `466a226` / `a53eda8` and the existing signed digest `94F65BCC…` are unchanged.
- Does **not** close `soak_24h`. The board remains **5/6 PASS, NOT SHIPPABLE**. The real `225843` verdict is `FAIL` and the window is VOID (#55).
- Does **not** create E5, E6 or E7 qualification. No HLK/WHQL result, catalog file, Authenticode signature or driver-load evidence exists in the environment; none was invented.
- Does **not** alter the release gate. The attestation lives under `analysis/`, not `release/`, so `tools/final_audit.py`'s signature scan is untouched.
- Does **not** touch the host, services, drivers, installed binaries, finalizers or any soak window.

## Scope boundary in one line

Real owner-key signature over a records-tip identity statement — evidence of *integrity of the honest record*, not evidence of shipability.
