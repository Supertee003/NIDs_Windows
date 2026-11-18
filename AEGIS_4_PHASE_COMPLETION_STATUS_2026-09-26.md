
## 2026-09-26 host-gate update

The final Administrator lifecycle proof passed: the runtime stopped and restarted, Rust Shield returned `READY`, forensic generation verified with `integrity=ok`, and the prevention gate was consistent with provider/host-effect capability. The final WFP read-only preflight also passed: Administrator=true, AegisWfp installed/running, PEP/provider/host-effect all true, and `enforcement_attempted=false`.

The preflight required two correctness fixes: it now accepts a serving authoritative health JSON even when the CLI process exit code is non-zero, and it treats a prevention gate as valid when provider readiness and host-effect capability are both true.

Before the real Kali-to-Windows host block proof, a driver semantic issue was found and must not be hidden by a successful receipt. The current driver adds filters at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` with `FWPM_CONDITION_IP_REMOTE_ADDRESS/PORT`. That is an outbound-connect filter. A request containing the Windows target address `192.168.126.20` therefore describes a remote endpoint for outbound traffic from Windows; it does not inherently block an inbound connection from Kali `192.168.126.10` to the Windows listener at `192.168.126.20:8080`. The requested inbound proof requires either an inbound `ALE_AUTH_RECV_ACCEPT_V4` direction-aware implementation or a separately defined outbound proof. No enforcement request has been sent after this finding.
