# AEGIS Control CLI Commands

The canonical client is `tools/aegisctl.py`. The support package lives under
`tools/aegisctl/` (client, console, components, graph, contracts, api,
web_dashboard). The retired command-module package is quarantined at
`tools/legacy/aegisctl_commands_quarantined/` and is not wired by the CLI.

The CLI talks to the runtime through the control protocol (named pipe) and
does not perform privileged WFP operations itself - privileged actions are
requests only; authorization and enforcement remain in the runtime and the
Rust PEP path.

## Commands

```powershell
python tools/aegisctl.py alerts
python tools/aegisctl.py authority
python tools/aegisctl.py block
python tools/aegisctl.py brain
python tools/aegisctl.py bridge
python tools/aegisctl.py canary
python tools/aegisctl.py components
python tools/aegisctl.py console
python tools/aegisctl.py dashboard
python tools/aegisctl.py diagnose
python tools/aegisctl.py enforce
python tools/aegisctl.py events
python tools/aegisctl.py federation
python tools/aegisctl.py forensic
python tools/aegisctl.py forensics
python tools/aegisctl.py graph
python tools/aegisctl.py health
python tools/aegisctl.py help
python tools/aegisctl.py incidents
python tools/aegisctl.py iptest
python tools/aegisctl.py metrics
python tools/aegisctl.py policy
python tools/aegisctl.py quarantine
python tools/aegisctl.py queue
python tools/aegisctl.py readiness
python tools/aegisctl.py restart
python tools/aegisctl.py rules
python tools/aegisctl.py simulate
python tools/aegisctl.py snapshot
python tools/aegisctl.py start
python tools/aegisctl.py status
python tools/aegisctl.py stop
python tools/aegisctl.py version
```

Nested command help is available from the parent command, for example:

```powershell
python tools/aegisctl.py rules --help
python tools/aegisctl.py forensic --help
python tools/aegisctl.py policy --help
```

Role-oriented command map: `docs/OPERATOR_COMMAND_MAP.md`.
