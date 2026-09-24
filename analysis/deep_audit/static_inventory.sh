#!/usr/bin/env bash
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/analysis/deep_audit/static_inventory.md"
cd "$ROOT"
{
  echo "# Static Inventory and Contract Scan"
  echo
  echo "Generated from tracked files in source-of-truth: $ROOT."
  echo
  echo "## Repository state"
  echo
  echo '```text'
  git branch --show-current 2>&1 || true
  git diff --stat 2>&1 || true
  git diff --name-status 2>&1 || true
  echo '```'
  echo
  echo "## Tracked file count"
  echo
  echo '```text'
  git ls-files | wc -l
  echo '```'
  echo
  echo "## Files by extension"
  echo
  echo '```text'
  git ls-files | awk '
  function ext(path, base,n,a){n=split(path,a,"/"); base=a[n]; if (base !~ /\./) return "[no extension]"; sub(/^.*\./,"",base); return "." base}
  {c[ext($0)]++} END {for (e in c) print e, c[e]}' | sort
  echo '```'
  echo
  echo "## Source line counts"
  echo
  echo '```text'
  git ls-files '*.zig' '*.rs' '*.go' '*.c' '*.h' '*.cpp' '*.py' '*.ps1' '*.bat' '*.sh' '*.ts' '*.tsx' '*.js' '*.jsx' '*.nsi' '*.toml' '*.yaml' '*.yml' '*.json' | while IFS= read -r f; do [ -f "$f" ] && wc -l "$f"; done | awk '{sum += $1; print} END {print "TOTAL", sum}' | sort -k2,2nr | head -160
  echo '```'
  echo
  echo "## Authority and enforcement-related matches"
  echo
  echo '```text'
  git grep -n -I -E 'block_ip|unblock_ip|netsh|FwpmFilterAdd|FwpmFilterDeleteById|enforcement\.block|enforcement\.unblock|filter_id|PepRequest|PepResponse|policy_authority|host_effect|BLOCKED_CONFIRMED|ENFORCED' -- ':!analysis/deep_audit/*' 2>&1 || true
  echo '```'
  echo
  echo "## Placeholder and fail-closed markers"
  echo
  echo '```text'
  git grep -n -I -E 'TODO|FIXME|XXX|NotImplemented|not implemented|stub|placeholder|fail.closed|fail_closed|return false|return null|pass$|raise NotImplemented' -- ':!analysis/deep_audit/*' 2>&1 || true
  echo '```'
  echo
  echo "## Potential unsafe or process-boundary operations"
  echo
  echo '```text'
  git grep -n -I -E 'unsafe|CreateProcess|CreateFile|DeviceIoControl|OpenProcess|Impersonate|CreateNamedPipe|CreateNamedPipeW|subprocess|os\.system|system\(|popen|ctypes|dlopen|LoadLibrary|spawn|Thread|Mutex|semaphore|atomic|lock|sleep|timeout' -- ':!analysis/deep_audit/*' 2>&1 || true
  echo '```'
  echo
  echo "## Tests and manifests"
  echo
  echo '```text'
  git ls-files 'tests/**' 'src/tests/**' 'test_*.py' '*_test.go' '*_test.rs' '*_test.zig' 'runtime_manifest.json' 'build_manifest.json' 'inventory.json' 'reference_map.json' 'EVIDENCE_INDEX.json' 'ci_coverage.json' | sort
  echo '```'
} > "$OUT"
printf '%s\n' "$OUT"
