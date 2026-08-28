# AEGIS NIDS — Language Ownership (Rewrite v3.0)

## Status: FROZEN — Changes require ADR

## Ownership Matrix

| Language | Role | Owns | Does NOT Own |
|----------|------|------|-------------|
| **Zig** | System Coordinator | Core runtime, Event Fabric, Flow engine, Detection orchestration, Correlation orchestration, Windows-native coordination | Packet parsing (C++), Enforcement (Rust), Acquisition (Go), Intelligence (Python) |
| **C** | ABI Boundary | Wire primitives, Fixed-width types, Stable native boundary, ABI definitions | Business logic, Detection, Policy |
| **C++** | Adapter | Native compatibility, Windows bridge, Legacy adapter, Transport compatibility, Existing native components | Detection logic, Policy decisions, Central brain |
| **Go** | Acquisition Boundary | Nose, Collectors, Acquisition, External aggregators, I/O concurrency, Sensor orchestration, REST API | Detection, Policy, Enforcement |
| **Rust** | Security Authority | Security boundary, Policy validation, PEP, Enforcement state, Integrity, Rollback, Sensitive state | Detection logic, Intelligence, Acquisition |
| **Python** | Intelligence Control | Brain orchestration, Analytics, RAG, Research, Model lifecycle, Offline experimentation | Direct enforcement, Firewall operations, PEP |
| **Cython** | Accelerator | Feature extraction, Numeric hot paths, Preprocessing, Performance-critical Brain computation | Business logic, Policy, Enforcement |

## Key Principles

### Zig = System Coordinator
- ไม่ใช่ทุกอย่างต้องเขียนด้วย Zig
- Zig เป็น spine ที่เชื่อมทุกส่วน
- เรียก FFI ไปยังภาษาอื่นได้โดยตรง

### C = ABI Boundary
- ต้องเล็กและเสถียร
- เป็นจุดเชื่อมระหว่างภาษาทั้งหมด
- Fixed-width types เท่านั้น

### C++ = Adapter
- เป้าหมาย: C++ Bridge = adapter (ไม่ใช่ central brain)
- ใช้สำหรับ Windows compatibility และ legacy components
- Zero-copy packet parsing เป็น core competency

### Go = Acquisition Boundary
- ต้องเป็น Acquisition Boundary (ไม่ใช่ detector)
- I/O concurrency เป็นจุดแข็ง
- REST API + alert aggregation

### Rust = Security Authority
- รับ EnforcementPlan → validate → execute
- ตรวจ: policy_version, policy_signature, target, action, authorization, expiry
- ไม่รับ arbitrary JavaScript/input

### Python = Intelligence Control
- Brain orchestration, RAG, analytics, model lifecycle
- ส่ง: score, confidence, features, context, recommendation
- ห้าม: direct enforcement (firewall.block)

### Cython = Accelerator
- Feature extraction, hot loops, numeric scoring
- เร่งความเร็ว Python Brain เท่านั้น
