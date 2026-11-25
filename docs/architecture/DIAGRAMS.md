# AEGIS diagrams — component, lifecycle, trust boundary

> Scope: production `v1.1` observe-only runtime at build source `7822f4c`
> (prior `43a8bcc` scope is HISTORICAL).
> These diagrams describe source-described routes; they are not Windows E5 proof.
> Lab-only host-effect stages are labelled and are not part of production.
> Data flow and control flow use different edge styles. Validation points are marked `Vn`.

---

## Diagram 1 — Component architecture

```mermaid
flowchart LR
  subgraph EXT["External network"]
    NET["Network traffic"]
  end

  subgraph KERNEL["Kernel mode"]
    NPCAP["Npcap capture"]
    WFP["WFP callout — observe-only telemetry"]
    ETW["ETW"]
    FIM["FIM minifilter"]
    REG["Registry telemetry"]
  end

  subgraph USER["User mode"]
    NOSE["Go Nose — acquisition"]
    PIPE["\\\\.\\pipe\\aegis_nose<br/>4-byte LE length prefix"]
    ZIG["Zig daemon — single runtime authority"]
    QUEUE["Bounded queue + drop/shed counters"]
    DETECT["Rule engine / correlation"]
    PEP["Rust PEP — detection-only evaluation"]
    EVID["Hash-chained forensic records"]
    BRAIN["Python Brain — advisory analytics"]
    UI["CLI / read-only dashboards"]
    CONTROL["\\\\.\\pipe\\aegis_control"]
  end

  NET --> NPCAP --> NOSE
  WFP --> ZIG
  ETW --> ZIG
  FIM --> ZIG
  REG --> ZIG
  NOSE -->|"data: CanonicalEvent frames"| PIPE --> ZIG
  ZIG --> QUEUE --> DETECT --> PEP
  PEP -->|"evidence assessment only"| EVID
  EVID --> BRAIN --> UI
  UI -->|"control: authenticated requests"| CONTROL --> ZIG
  ZIG -->|"daemon-owned snapshot"| CONTROL

  classDef data fill:#e8f3ff,stroke:#2b6cb0;
  classDef ctrl fill:#fff3e0,stroke:#b7791f;
  class NET,NPCAP,NOSE,PIPE,WFP,ETW,FIM,REG,QUEUE,DETECT,PEP,EVID,BRAIN data;
  class CONTROL,UI ctrl;
```

Notes:

- Solid blue edges are **data/evidence flow**; orange edges are **control flow**.
- Go Nose is the canonical acquisition path. Direct Npcap in Zig is a disjoint
  lab-only sensor and never a second production ingress.
- The production WFP filter is observe-only telemetry. Block IOCTL returns
  `STATUS_NOT_SUPPORTED`; no production component authorizes a host effect.
- Rust PEP returns an assessment; a PEP decision or receipt is not evidence of a
  host effect (`RETIRE-HOST-EFFECT-001`, `AUTHORITY_MAP.json`).

---

## Diagram 2 — Event lifecycle (production)

```mermaid
flowchart TD
  A["Network / host activity"] --> B["Sensors<br/>Go Nose, WFP, ETW, FIM, Registry"]
  B --> V1{"V1 — source validation<br/>length, schema, truncation flag"}
  V1 -->|reject + counter| X["Rejected / counted<br/>no silent loss"]
  V1 -->|accept| C["Event acquisition<br/>length-prefixed IPC"]
  C --> V2{"V2 — exact-length codec<br/>version, trailing bytes, max size"}
  V2 -->|reject + counter| X
  V2 -->|accept| D["CanonicalEvent / IpcEvent"]
  D --> E["Zig runtime — bounded queue<br/>drop and shed counters"]
  E --> F["Detection engine — 23 rules"]
  F --> G["Policy evaluation — Rust PEP<br/>detection-only"]
  G --> H["Evidence / alert<br/>hash-chained record"]
  H --> I["Investigation<br/>CLI, dashboards, integrity verify"]

  A -.->|"control: operator query"| I
  I -.->|"control: authenticated request"| E

  LAB["LAB-ONLY build gate:<br/>authorize / apply / verify host effect"] -.->|"not compiled into production"| G
```

Notes:

- Production stops after policy evaluation: the decision is recorded as evidence.
  Steps `authorize / apply / verify` exist only in the separately compiled lab gate.
- `V1` and `V2` are validation points. Rejections increment observable counters
  (`nose_frames_rejected`, `queue_drops`, shed counters); they are not silent.
- Event time (`timestamp_ms`, `monotonic_ns`) is preserved from the producer; the
  wall clock is used only for liveness, not to overwrite producer time.
- Known gap: R2003 (PowerShell cradle) has no `CommandLine` producer in v0–v4
  process telemetry, so it is catalogued but host-inert (FN-1).

---

## Diagram 3 — Trust boundary

```mermaid
flowchart TB
  subgraph BOUND_EXT["External network — untrusted"]
    N["Packets"]
  end

  subgraph BOUND_KERNEL["Kernel mode — evidence source, not authority"]
    K["WFP / ETW / FIM / Registry"]
  end

  subgraph BOUND_USER["User mode"]
    S["Go Nose / adapters — untrusted producers"]
    V1{"V1: decode + bounds check"}
    IPC["Named-pipe IPC<br/>aegis_nose / aegis_control"]
    V2{"V2: exact length + framing"}
    Z["Zig daemon — authoritative runtime state"]
    V3{"V3: schema + capability check"}
    P["Rust PEP — detection-only"]
    E["Evidence storage — tamper-evident hash chain"]
    C["Config / policy artifacts — signed or verified"]
    U["CLI / dashboards — render snapshots only"]
  end

  N --> K --> S --> V1 --> IPC --> V2 --> Z --> V3 --> P --> E
  C --> V3
  Z --> U
  U -.->|control| Z

  classDef boundary fill:#fff5f5,stroke:#c53030,stroke-width:2px;
  class V1,V2,V3 boundary;
```

Notes:

- Blue/orange distinction from Diagram 1 applies here as well: producer-to-runtime
  edges are data; operator-to-runtime edges are control.
- A malicious local process may open named pipes; authorization is enforced at
  `V3` by the Zig daemon. `provider_ready=true` is not a host-effect authorization
  and is projected as `host_effect_capable=false` in production.
- Kernel administrator or higher OS control is **outside** what a user-mode NIDS
  can defend. The system is tamper-evident, not tamper-proof. See
  [`docs/SECURITY_THREAT_MODEL.md`](../SECURITY_THREAT_MODEL.md).
- Evidence storage integrity is hash-chain verification after the fact; it is not
  replay re-execution and not a claim of "zero loss ever".

---

Source-of-truth pointers (do not duplicate their content here):

- Canonical event schema: `shared/event/canonical_event.md` (FROZEN)
- Wire framing: `shared/protocol/wire_v1.md`, `wire_v2.md`, `wire_v3.md` (ACTIVE)
- Authority: `AUTHORITY_MAP.json`, `docs/architecture/authority-matrix.md`
- Runtime contract: `docs/runtime/RUNTIME_CONTRACT.md`
