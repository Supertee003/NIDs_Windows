from pathlib import Path
import re

FILES = [
    Path('scripts/aegis_console_pro.py'),
    Path('scripts/Dashboard.py'),
    Path('scripts/aegis_console.py'),
]

BLOCK = '''COMPONENT_LABELS = {
    "control": "CONTROL DAEMON",
    "cpp": "C++ BRIDGE",
    "forensic": "FORENSIC PLANE",
    "go": "GO NOSE",
    "rust_pep": "RUST MOUTH / PEP",
    "tier3": "PYTHON BRAIN / TIER3",
    "zig": "ZIG CORE",
}
'''

for path in FILES:
    if not path.exists():
        raise SystemExit(f'MISSING_FILE: {path}')
    text = path.read_text(encoding='utf-8-sig')

    # Remove every previously inserted mapping block, wherever the v1 patch put it.
    text = re.sub(
        r'(?ms)^COMPONENT_LABELS\s*=\s*\{.*?^\}\s*\n',
        '',
        text,
    )

    # Put the mapping before the first executable function. This guarantees
    # module-global scope and keeps it outside module/class docstrings.
    match = re.search(r'(?m)^def\s+', text)
    if not match:
        raise SystemExit(f'FIRST_FUNCTION_NOT_FOUND: {path}')
    insert_at = match.start()
    prefix = text[:insert_at]
    suffix = text[insert_at:]
    if prefix and not prefix.endswith('\n\n'):
        prefix = prefix.rstrip('\n') + '\n\n'
    text = prefix + BLOCK + '\n' + suffix
    path.write_text(text, encoding='utf-8', newline='')
    print(f'FIXED: {path}')

print('PATCH_OK: COMPONENT_LABELS is now module-global in all UI files')
