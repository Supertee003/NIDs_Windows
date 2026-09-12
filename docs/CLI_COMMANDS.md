# AEGIS Control CLI Commands

The canonical client is `tools/aegisctl.py`. The command modules live under
`tools/aegisctl/commands/` and communicate with the runtime through the
control protocol. The CLI does not perform privileged WFP operations itself.

## Read and Operations

```powershell
python tools/aegisctl.py alerts
python tools/aegisctl.py api
python tools/aegisctl.py backup
python tools/aegisctl.py block
python tools/aegisctl.py canary
python tools/aegisctl.py console
python tools/aegisctl.py dashboard
python tools/aegisctl.py diagnose
python tools/aegisctl.py enforce
python tools/aegisctl.py events
python tools/aegisctl.py federation
python tools/aegisctl.py forensic
python tools/aegisctl.py health
python tools/aegisctl.py incidents
python tools/aegisctl.py logs
python tools/aegisctl.py metrics
python tools/aegisctl.py policy
python tools/aegisctl.py quarantine
python tools/aegisctl.py restart
python tools/aegisctl.py restore
python tools/aegisctl.py rules
python tools/aegisctl.py simulate
python tools/aegisctl.py start
python tools/aegisctl.py status
python tools/aegisctl.py stop
python tools/aegisctl.py version
python tools/aegisctl.py watchdog
```

Nested command help is available from the parent command, for example:

```powershell
python tools/aegisctl.py rules --help
python tools/aegisctl.py forensic --help
python tools/aegisctl.py policy --help
```

Privileged actions are requests only. Authorization and enforcement remain in
the runtime and Rust PEP path.
