# AEGIS Final Regression (T20 AC1, Step 60)

- Generated: 2026-09-08T06:47:38.666825+00:00
- Full pytest suite: **FAIL**
- Subsystems: 14 pass / 2 fail / 16 total
- Known partial (unaudited): driver, installer, upgrade, rollback
- [ ] Gap: subsystem FAIL

| subsystem | result | runs | failures |
|---|---|---|---|
| unit | PASS | 4 | 0 |
| integration | PASS | 4 | 0 |
| contracts | PASS | 2 | 0 |
| windows-host | PASS | 4 | 0 |
| driver | PASS | 4 | 0 |
| fault | PASS | 5 | 0 |
| security | PASS | 7 | 0 |
| performance | PASS | 4 | 0 |
| tls | PASS | 2 | 0 |
| federation | PASS | 3 | 0 |
| installer | PASS | 5 | 0 |
| upgrade | FAIL | 2 | 1 |
| rollback | FAIL | 2 | 1 |
| replay | PASS | 3 | 0 |
| ips | PASS | 4 | 0 |
| xdr | PASS | 3 | 0 |

Failing detail - upgrade:
- pytest tests/release rc=1 1 failed, 15 passed in 0.66s
Failing detail - rollback:
- pytest tests/release rc=1 1 failed, 15 passed in 0.90s
