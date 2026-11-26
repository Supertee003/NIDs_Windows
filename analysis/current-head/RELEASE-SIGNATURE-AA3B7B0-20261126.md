# New release signature record at build source `aa3b7b0` — 2026-11-26

**RECORD-ID:** `RELEASE-SIGNATURE-AA3B7B0-20261126`
**RECORDS HEAD / RELEASE COMMIT:** `6c94b47dc95acfef283cf24727e6edf2f2647e47` (short `6c94b47`)
**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5`
**EVIDENCE LEVEL:** E1/E2 static + cryptographic verification of the release record. It does **not** promote the release to E5/E7 by itself.

## Why a new record

`release/T20-final/466a226/signatures.json` predates the current runtime source and therefore cannot satisfy `final_audit.py::evaluate_signature` (`commit_contains_runtime` false). The published `v1.1` identity — commit `466a226`, signed artifact `a53eda8`, and its original signature — is **left untouched**. This record is an additional tree for the current source, not a rewrite of history or a re-labelling of the old release.

## Key custody (owner-approved)

The owner explicitly approved generating a new Ed25519 release key. It was created with the repository tool and stored **outside the tracked tree**:

- private key: `D:\aegis-tmp\keys\aegis-release-aa3b7b0.ed25519` (raw 32-byte seed, restrictive permissions); owner must back it up offline. Never commit it.
- public key (base64 raw 32 bytes, the trust anchor): `DCNPphsqfklICz6MxxfS5jP005BOOGbug8Vxgpn8cZU=`
- trust anchor supplied to the audit as `AEGIS_RELEASE_TRUSTED_PUBLIC_KEY` exactly as above.

No private key bytes appear in any tracked file, log, or this document.

## What was built

Both kernel driver outputs were rebuilt from the authoritative current sources with WDK (`scripts/wdk_build_production.ps1` / `scripts/wdk_build_minifilter.ps1`), not copied from archives:

| Artifact | SHA-256 |
|---|---|
| `build/x64/wfp/aegis_wfp.sys` | `593A1299F9A1EB84F77582FDB17AC3E20AF4CA43CB76AF43CE4E8102F9CA3895` |
| `build/x64/minifilter/aegis_minifilter.sys` | `3EE10E8220A9113CF490E1CF75C02DFC6200DEA8BD098FD81C5390725C0E0E70` |

The release tree uses the **exact PEP binary proven on the host** at this source (`6E05AAE1BAE000C8D2C1A841EFF9B65035E5131066FFB43800AD414659564926`) rather than a differently-pathed local rebuild whose embedded metadata produced another digest. The daemon binary is `6F548AF7641C1C476FB591D165ED734027ED18D93F980AFEA755C20A716BBB98`.

## Commands and observed results

```text
python tools/release_candidate.py
  RC PASS: release/T20-final/6c94b47 (270 files)

python tools/release_candidate.py --verify --dir release/T20-final/6c94b47
  RC VERIFY PASS

python tools/sign_release.py --sign --dir release/T20-final/6c94b47 \
    --key-file D:\aegis-tmp\keys\aegis-release-aa3b7b0.ed25519
  signed SHA256SUMS -> signatures.json
  digest: 94F65BCC7B6D4E9C1CA977D1D74BAE4DCACD85CD4698754FEB3F1985EA15B1AE
  public key: DCNPphsqfklICz6MxxfS5jP005BOOGbug8Vxgpn8cZU=

python tools/sign_release.py --verify --dir release/T20-final/6c94b47
  PASS: signatures.json signs SHA256SUMS (94F65BCC7B6D4E9C...)

AEGIS_RELEASE_TRUSTED_PUBLIC_KEY=DCNPphsqfklICz6MxxfS5jP005BOOGbug8Vxgpn8cZU= \
  python tools/final_audit.py --check
  PASS release_signature [owner] ... commit 6c94b47 contains runtime aa3b7b0
  overall: NOT SHIPPABLE (1/6 gates open — soak_24h still covering a pre-current build)
```

The signature covers the bytes of `SHA256SUMS`; recomputing that digest is how `final_audit.py` detects any later change to the shipped file list.

## Remaining gates

- `soak_24h` must be closed by the fresh 24 h current-source window recorded in `owner-soak-aa3b7b0-20261126-162907`; until that window ends and is evaluated, the release remains NOT SHIPPABLE.
- Driver images are WDK-built from source but are not claimed as production-signed or production-installed here; existing KNOWN_LIMITATIONS still apply.
