# Transcode provenance - `raw-aa3b7b0-20261126`

**BUILD SOURCE:** `aa3b7b0` (unchanged).  
**RECORDS SCOPE:** encoding provenance only; no evidence level, result, gate or verdict changed.

Commit `848c924` transcoded ten UTF-16LE raw text artifacts to UTF-8/LF so the
CI encoding guard can read them. The pre-transcode bytes are preserved verbatim
in git at `848c924^`; each sidecar records that original SHA-256, the current
SHA-256, and a reproducible byte-exactness check. The operator externals remain
outside the tree; no host file was touched by this reconciliation.

| Sidecar | File | Original UTF-16LE SHA-256 | Current UTF-8 SHA-256 |
|---|---|---|---|
| `TRANSCODE-SIDECAR-AA3B7B0-20261126-01` | `analysis/current-head/raw-aa3b7b0-20261126/fuzzbench/aa3_perf_latency.log.transcode.json` | `3c09d88f2c269ce52c1714d19cd23567f123e5d101735d5373d3ee8713517f37` | `c8eb8b8ba76305c9791ade8e6302cb92c45c0c94863dc8d73af06dcd3d4be80c` |
| `TRANSCODE-SIDECAR-AA3B7B0-20261126-02` | `analysis/current-head/raw-aa3b7b0-20261126/fuzzbench/aa3_perf_quick.log.transcode.json` | `905afeb2b1697f5dc2e85e2c6a7f1a8d5ecbe412790bf2e268201efea4f5bc9a` | `bff1f640d2a2ea726c804a70496602bb7684b0989c6ed77e78c81c404c36a7c1` |
| `TRANSCODE-SIDECAR-AA3B7B0-20261126-03` | `analysis/current-head/raw-aa3b7b0-20261126/r2003-e5/v1-baseline_r2003.raw.txt.transcode.json` | `026d33d806bcd85c0185081a629bbe2230212e640d3de6675c00dc3186f48fb8` | `d61415713028f043a3570f32d4e32d115ace4d9de1ece04cf73071da423b7a64` |
| `TRANSCODE-SIDECAR-AA3B7B0-20261126-04` | `analysis/current-head/raw-aa3b7b0-20261126/r2003-e5/v1-negative_wire_marker.raw.txt.transcode.json` | `179b7f940e9108517188b0c8a88965a977d2f959225259f63e0789b067ece69b` | `29d13ffc11a320e063402700bba9f6190133001c19d1ba8ede6cdf52e8903abd` |
| `TRANSCODE-SIDECAR-AA3B7B0-20261126-05` | `analysis/current-head/raw-aa3b7b0-20261126/r2003-e5/v1-positive_marker.raw.txt.transcode.json` | `481af81ed222056e92bc8500cb9b3306e165aa9e38d5e0b8fecc3149f5289bd7` | `6627f1c64592ecafbb0bdef12ad34f36188c94644012d56d4468f9e2205d5c97` |
| `TRANSCODE-SIDECAR-AA3B7B0-20261126-06` | `analysis/current-head/raw-aa3b7b0-20261126/r2003-e5/v2-baseline_r2003.raw.txt.transcode.json` | `86d82af979c09259d4193e72c6956882b0476c5931d8305c00c1a262d29b7f99` | `b1f58287b98181e1135ae454094612be3b2aba24c629a0e796d9af5aac0d2df5` |
| `TRANSCODE-SIDECAR-AA3B7B0-20261126-07` | `analysis/current-head/raw-aa3b7b0-20261126/r2003-e5/v2-negative_cmd_marker.raw.txt.transcode.json` | `3d69a17ff36cbe51d5512b4656b7c6c057f8654c5cf169db871ffaeb86236d63` | `3d1988e791376ab2c5d2a7b62aa12818f09f2a5b5b7791dd4d6284ccf84dd3d4` |
| `TRANSCODE-SIDECAR-AA3B7B0-20261126-08` | `analysis/current-head/raw-aa3b7b0-20261126/r2003-e5/v2-negative_wire_marker.raw.txt.transcode.json` | `a2e74dfebd223e451c7b0b54a8c96c3c6713447d40d4bee7ea750eaaeb2c752b` | `1a736396f4578476d11e57c0714359ee0e6270d79f082cb4476c44f78df62e93` |
| `TRANSCODE-SIDECAR-AA3B7B0-20261126-09` | `analysis/current-head/raw-aa3b7b0-20261126/r2003-e5/v2-positive_marker.raw.txt.transcode.json` | `8223206bfecaac52b1f73098b32942cf8432ae5e1e0183ca6f78263bf1e1d799` | `e49c5b4d3da2f662af867b0b674a95fff2d0e58a93fb7cf5a724dae3affd2778` |
| `TRANSCODE-SIDECAR-AA3B7B0-20261126-10` | `analysis/current-head/raw-aa3b7b0-20261126/shutdown-e5/i44_e45_aa3b7b0_inject.txt.transcode.json` | `0156d298f1e3f3725c13862c771324164801ac571405d9673b9279d54290b206` | `9e2cbf1c9b4952fcda17911aade6ddcee0286c73bd0e3056bb8622fcbd3f6f86` |

Verification used for every row: `git show 848c924^:<file>` -> decode as UTF-16
(BOM consumed) -> replace CRLF with LF -> encode UTF-8 -> compare with the
committed bytes. All ten comparisons were byte-identical. The originals were
not restored into the tree; doing so would reintroduce the UTF-16 BOM the guard
rejects.
