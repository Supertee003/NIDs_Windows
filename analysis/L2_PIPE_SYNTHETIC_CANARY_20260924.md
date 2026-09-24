# L2_PIPE Synthetic Rule Canary

**Status:** `PASS`

This scan checks in-memory pipe-name fixtures against the native prefix matcher and configured rule regexes. It does not create a named pipe, perform remote execution, or invoke enforcement.

| Rule | Positive | Sensor+ | Sensor- | Regex+ | Regex- |
|---|---|---:|---:|---:|---:|
| `R3001` | `MSSE-1234` | `True` | `False` | `True` | `False` |
| `R3002` | `psexec-svc` | `True` | `False` | `True` | `False` |
| `R3003` | `anonymous-channel` | `True` | `False` | `True` | `False` |
| `R3004` | `meterpreter-ctrl` | `True` | `False` | `True` | `False` |
| `R3005` | `atsvc-job-1` | `True` | `False` | `True` | `False` |

## Findings

- All five pipe rules matched their positive fixture and rejected their benign fixture in both matching layers.

## Sensor boundary note

The canary proves name matching only. Full pipe-sensor qualification still requires a captured native enumeration event, canonical event, forensic record, and observe-only host-effect proof; prevention remains closed.

