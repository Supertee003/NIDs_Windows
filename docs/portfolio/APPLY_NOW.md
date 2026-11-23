# Apply now — ready-to-use job application kit

Everything below is copy/paste ready. Use it today; the project does not need to be "more complete"
before you apply. The published `v1.1` release is signed, soak-tested, and detection-only.

## Links

| Asset | URL |
|---|---|
| Repository | https://github.com/Supertee003/NIDs_Windows |
| 1-minute README (with real screenshot) | https://github.com/Supertee003/NIDs_Windows#aegis-in-60-seconds |
| 2:27 live demo (traffic → event → detection → dashboard → forensic record) | https://github.com/Supertee003/NIDs_Windows/blob/main/docs/portfolio/images/demo.mp4 |
| Architecture explained in English | https://github.com/Supertee003/NIDs_Windows/blob/main/docs/portfolio/ARCHITECTURE_EN.md |
| Resume project section | https://github.com/Supertee003/NIDs_Windows/blob/main/docs/portfolio/RESUME_PROJECT.md |
| Demo script / chapter guide | https://github.com/Supertee003/NIDs_Windows/blob/main/docs/portfolio/DEMO.md |
| Scope and status table (IDS vs IPS, one answer) | https://github.com/Supertee003/NIDs_Windows#scope-and-status-in-one-table |
| Detection rule catalog | https://github.com/Supertee003/NIDs_Windows/blob/main/docs/portfolio/DETECTION_CATALOG.md |
| Security threat model | https://github.com/Supertee003/NIDs_Windows/blob/main/docs/SECURITY_THREAT_MODEL.md |
| Source-level interview preparation | https://github.com/Supertee003/NIDs_Windows/blob/main/docs/portfolio/INTERVIEW_PREP.md |

---

## 30-second pitch (Use this everywhere)

> I built AEGIS NIDS Windows, a Windows-native, kernel-assisted network intrusion detection
> system. It turns real packet and host telemetry into one canonical event, runs 23 detection
> rules, and writes hash-chained forensic evidence with an evidence receipt. The engineering
> challenge was authority: the runtime spans Zig, Go, Rust, C/C++, Python and TypeScript, but only
> one component owns the pipeline, and no layer can promote "detected" into "blocked." v1.1 shipped
> signed with a 36.5-hour soak PASS and a real Windows host detection proof with a negative control.

---

## LinkedIn headline (pick one)

- `Security Engineer | Windows Kernel-Assisted NIDS | Zig · Go · Rust · C++ · Python`
- `Detection Engineer | Built a 6-language Windows NIDS with hash-chained forensics`
- `SOC / Detection Engineering | Windows telemetry, canonical event pipelines, detection-only architecture`

## LinkedIn "About" section

> I build detection systems for Windows. My flagship project, AEGIS NIDS Windows, is a
> kernel-assisted network intrusion detection system with a six-language hub-and-spoke runtime:
> Zig owns the event pipeline, Go captures packets, C/C++ adapters read WFP/ETW/file/registry
> telemetry, Rust is the detection-only policy and crypto authority, Python handles analytics, and
> TypeScript authors policy. The design enforces a hard boundary — findings become hash-chained
> forensic evidence, never a host block.
>
> What I care about: canonical contracts across languages, verifiable evidence over claims, and
> fail-closed behavior. Published v1.1 is signed, 674/674 artifacts verified, and soak-tested for
> 36.52 hours with zero loss counters. Detect, record, prove — don't pretend.

---

## Recruiter cold email / DM template

**Subject:** Windows NIDS with real detection evidence — quick portfolio

> Hi [Name],
>
> I'm a security engineer with a shipped Windows kernel-assisted NIDS you can inspect end-to-end:
> https://github.com/Supertee003/NIDs_Windows
>
> It's a six-language runtime (Zig/Go/Rust/C++/Python/TypeScript) with a canonical event pipeline,
> 23 detection rules, hash-chained forensics, and a strict detection-only authority boundary. The
> README has a 1-minute summary and a real screenshot; there's a 2.5-minute demo that goes from
> traffic to a verified forensic record. v1.1 is signed and soak-tested (36.5 h, zero loss).
>
> Would you be open to a 15-minute call? I can walk through the architecture and the evidence.
>
> Thanks,
> [Your name]

---

## Target roles and keywords

**Roles:** Detection Engineer · Security Engineer (Windows) · SOC Engineer · Threat Detection
Engineer · Endpoint/Host Telemetry Engineer · Network Security Engineer · Security Platform
Engineer · Detection & Response Engineer.

**ATS keywords:** Windows internals, WFP, ETW, Npcap, packet capture, intrusion detection, NIDS,
canonical event schema, SOC, detection engineering, rule authoring, Rust, Zig,
Go, C++, Python, TypeScript, Ed25519 signing, hash chains, forensic integrity, fail-closed,
observability, SSE dashboard, pytest.

---

## Three interview answers to have ready

1. **"Isn't this just an IDS with rules?"** — The hard part isn't the regex; it's the authority
   model. One canonical event schema with byte-exact codecs (Zig/Go/C/Python), one runtime owner, and a Rust policy evaluator
   that can only produce evidence. Steps that might mutate a host exist only in a separately
   compiled lab gate; production cannot open the prevention gate.

2. **"How do you know detection works?"** — Real Windows E5 lab proof: a bounded SYN burst was
   attributed by exact 5-tuple to R9006 with a 10-port negative control that produced zero hits;
   a bridged-Kali window attributed 15 rows across multiple rules with zero drop/shed/quota deltas.
   Everything else is stated honestly: all 23 rules have synthetic fixtures, live proof is strongest
   on L4.

3. **"Did it actually block anything?"** — No. That is by design. A `BLOCK` label is intent; only a
   receipt with a verified host postcondition could claim a block, and this build cannot produce
   one. That boundary is the product.

---

## Application tracker (copy into a spreadsheet)

| Company | Role | Link | Date applied | Referral? | Follow-up date | Status | Notes |
|---|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |  |

**Cadence:** apply in batches of 10–15 per week. Follow up 5–7 business days after applying.
Use the 30-second pitch in the first message; lead with the repo, not the feature list.

---

## Non-negotiable claims guardrail

Never say: IPS, blocks traffic in production, EV/HLK signed driver, Microsoft attestation,
Signed-IR promotion, production fleet deployment, all 23 detections live-proven, or a fake soak.
Say: **Windows kernel-assisted NIDS, detection-only, real evidence, fail-closed.**

See [Architecture](ARCHITECTURE_EN.md) and [Resume section](RESUME_PROJECT.md) for the full facts.
