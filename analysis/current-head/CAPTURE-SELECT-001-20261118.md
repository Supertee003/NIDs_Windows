# CAPTURE-SELECT-001 - capture decisions are made on device identity, not spelling

**Created:** 2026-11-18
**Build source before this slice:** `aa42fca`
**Level:** E2 (unit pins) + one read-only host measurement (E1)

---

## 1. Finding

Two readers can exist on this host: the canonical Go Nose (`AEGIS_NOSE_IFACE`
or auto-select) and the daemon's optional direct Npcap reader
(`AEGIS_DAEMON_IFACE`, EVT-200). The daemon refuses the direct reader when the
two selectors "overlap", but the predicate compared **spellings**:

```zig
// before: src/capture/npcap_adapter.zig
pub fn interfaceSelectorsDisjoint(direct, nose) bool {
    return indexOf(d, n) == null and indexOf(n, d) == null;
}
```

A GUID and a description name one adapter without sharing a substring:

```
nose   = \Device\NPF_{CE375996-106D-46F7-A67C-0168EAE8C96F}
daemon = VMnet1
```

`interfaceSelectorsDisjoint` returns `true` for that pair, so the guard would
enable a second reader on the adapter the canonical reader already owns. Two
readers on one segment do not produce a second detection: they produce
duplicate canonical events and a second ingress identity, which is exactly what
the daemon comment says must never happen. The mirror image is the operator
failure measured in `LAB-WIFI-001-20261116.md`: a hand-typed selector pointed
the sensor at a segment nobody attacked, and silence was read as a detector
defect.

## 2. Change

| File | Change |
|---|---|
| `src/capture/npcap_adapter.zig` | `DeviceView`, `resolveSelector` (exact canonical name, else a **unique** case-insensitive name/description substring; zero or two matches resolve to nothing), `selectorsResolveDisjoint` (compares resolved device indices). `NpcapAdapter.open` resolves both selectors against one `pcap_findalldevs` table and returns `error.CaptureIfaceOverlapsNose` when they name one adapter, before any handle is opened. |
| `src/daemon.zig` | The pre-check is documented as a spelling-level gate; the adapter is named as the authority on device identity. Startup log says which level failed. |
| `tools/capture_select.py` | Operator surface: `--list`, `--show`, `--plan`, `--apply`, `--clear`, `--verify`. Resolves selectors the way the runtime does, refuses ambiguity, refuses overlap on resolved identity, pins the **canonical** device name (a later description rename cannot move the sensor), writes machine-scope variables only with `--apply`, and never restarts a service. |
| `docs/runbooks/RB-023-capture-segment-selection.md` | How to switch between Wi-Fi (bridged Kali, RB-022) and host-only VMnet1 (RB-021), including the restart cost and the verification gate. |
| `tests/tools/test_capture_select.py` | 20 pins: resolution, ambiguity, identity-based disjointness, verdicts, plan rendering, import hygiene. |
| `src/capture/npcap_adapter.zig` tests | Two new tests: `resolveSelector refuses ambiguity and never guesses`, `device identity, not selector spelling, decides disjointness`. |

`interfaceSelectorsDisjoint` is retained as the daemon's cheap pre-check and its
existing pins still pass; it is no longer the authority.

## 3. Host measurement (read-only, 2026-11-18)

```
$ python tools\capture_select.py --show
  devices seen      : 13
  nose pin          : \Device\NPF_{5FD31C6E-DE48-44CB-838E-14667A04DA4B}
  nose watches      : \Device\NPF_{5FD31C6E-...} (pin)
  attack target IP  : 192.168.1.39
  daemon pin        : \Device\NPF_{CE375996-106D-46F7-A67C-0168EAE8C96F}
  direct capture    : enabled (selectors resolve to two devices)
  verdict           : CAPTURE_SELECT_OK
```

```
$ python tools\capture_select.py --verify
capture device : \Device\NPF_{5FD31C6E-...}  Killer(R) Wi-Fi 6 AX1650i
target IPv4    : 192.168.1.39
preflight      : wire ingress advancing (+54 frames)
PREFLIGHT OK
```

Both readers are on disjoint devices today (Wi-Fi canonical, VMnet1 direct),
which is the intended lab shape; no duplicate ingress is possible from this
pair.

## 4. Verification

| Check | Result |
|---|---|
| `zig test ... npcap_adapter.zig` | 8/8 tests pass (includes the two new ones) |
| `python -m pytest -q tests/tools/test_capture_select.py` | 20 passed |
| `python -m pytest -q tests/tools/test_runbooks.py` | 4 passed (index matches files) |
| `zig build` | exit 0 |
| `tools/capture_select.py --show` / `--verify` | `CAPTURE_SELECT_OK`, ingress advancing |

## 5. Limitations

- No elevated window was available, so `--apply` (machine-scope write) and the
  service restart were **not** exercised on this host. The plan/apply split,
  the admin refusal path, and the rendered commands are covered by unit pins.
- The installed runtime still predates this change until the release build is
  installed (D3). Until then the running binaries keep the spelling-level
  guard; the adapter-level refusal is proven by unit tests and by `zig build`.
- Full-suite `zig build test` still ends with the known full-suite-only crash
  ("while executing test 'xdr.xdr_engine.test.XdrEngine prune', the following
  test command failed"). The same 11 XDR tests pass when run on their own, so
  this is the pre-existing interaction recorded in
  `analysis/SYSTEM_UNDERSTANDING_MAP.md` section 5.1, not a capture failure.
- `AEGIS_NOSE_IFACE` must name the device Go Nose opens. Go validates the exact
  canonical name, so the tool always pins canonical names; a description that
  Go would reject now fails closed at the adapter instead of arming a second
  reader.

## 6. Rollback

- Code: `git revert <this commit>` (the change is additive; the old predicate
  and its pins remain present).
- Host: `python tools\capture_select.py --apply --clear --role both` (or the two
  `REG DELETE` lines in RB-023), then `Restart-Service AegisNids`.

## 7. Remaining risk

- A future selector form neither exact-name nor unique-substring (for example a
  numeric index) must be added in one place: `resolveSelector`, with a pin. The
  operator tool and the runtime share that rule today.
- Restarting to inherit pins ends a soak window; RB-023 states that cost rather
  than hiding it.
