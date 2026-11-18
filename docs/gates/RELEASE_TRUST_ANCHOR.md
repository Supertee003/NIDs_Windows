# Release trust anchor (owner approval)

The `release_signature` gate has two independent checks
(`tools/final_audit.py::verify_detached_signature`): the detached Ed25519
signature must verify over the `SHA256SUMS` bytes, and the signing key must
match an owner-approved anchor supplied as `AEGIS_RELEASE_TRUSTED_PUBLIC_KEY`.
The second check is what separates "cryptographically signed" from "signed by
the release key", and it is deliberately fail-closed: no anchor, no pass.

## Approved anchor

```
txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o=
```

| Field | Value |
|---|---|
| Algorithm | Ed25519, raw 32-byte public key, base64 |
| Approved by | owner (Supertee003), 2026-11-18 |
| Private key custody | local only, `.keys/aegis-release.ed25519` (git-ignored, never committed) |
| First release signed with this key | `release/T20-final/ad7948c` |
| Current candidate signed with this key | `release/T20-final/bece8f1` |

This is not new key material. The key already signed `ad7948c`, so approving it
preserves continuity: the previous candidate and the current one verify under
one anchor. Re-keying would have re-signed the current candidate for no
security gain and broken that continuity.

## Operator use

```powershell
$env:AEGIS_RELEASE_TRUSTED_PUBLIC_KEY = 'txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o='
python tools\sign_release.py --verify --dir release\T20-final\bece8f1
python tools\final_audit.py --release-check
```

Both must pass. `sign_release.py --verify` checks the signature only;
`final_audit.py --release-check` is the gate that also demands the anchor, the
signed commit to be in HEAD's history, and that commit to contain the shipped
runtime commit.

## Rotation

If this key is ever lost or compromised: generate a new one with
`python tools\sign_release.py --generate-key .keys/aegis-release.ed25519`,
record the new public key here in a commit that also re-signs the candidate,
and update CI. The old key keeps verifying old trees — signatures do not
expire — so rotation is a forward operation, not a rewrite.