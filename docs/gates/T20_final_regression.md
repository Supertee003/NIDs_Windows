# AEGIS Final Regression (T20 AC1, Step 60)

- Generated: 2026-09-08T06:31:51.653631+00:00
- Full pytest suite: **FAIL**
- Subsystems: 12 pass / 4 fail / 16 total
- Known partial (unaudited): driver, installer, upgrade, rollback
- [ ] Gap: subsystem FAIL

| subsystem | result | runs | failures |
|---|---|---|---|
| unit | PASS | 4 | 0 |
| integration | PASS | 4 | 0 |
| contracts | PASS | 2 | 0 |
| windows-host | PASS | 4 | 0 |
| driver | FAIL | 3 | 1 |
| fault | PASS | 5 | 0 |
| security | PASS | 7 | 0 |
| performance | PASS | 4 | 0 |
| tls | PASS | 2 | 0 |
| federation | PASS | 3 | 0 |
| installer | FAIL | 5 | 1 |
| upgrade | FAIL | 2 | 1 |
| rollback | FAIL | 2 | 1 |
| replay | PASS | 3 | 0 |
| ips | PASS | 4 | 0 |
| xdr | PASS | 3 | 0 |

Failing detail - driver:
- tool policy validator rc=1 UnicodeEncodeError: 'charmap' codec can't encode character '\x9d' in position 1: character maps to <undefined>
Failing detail - installer:
- pytest tests/release rc=1 1 failed, 15 passed in 0.68s
Failing detail - upgrade:
- pytest tests/release rc=1 1 failed, 15 passed in 0.66s
Failing detail - rollback:
- pytest tests/release rc=1 1 failed, 15 passed in 0.65s
