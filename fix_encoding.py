#!/usr/bin/env python3
# Fix AI_CONTEXT.md encoding - replace problematic bytes with spaces
with open('AI_CONTEXT.md', 'rb') as f:
    data = f.read()

# Replace the problematic byte sequence at 1367-1369 with spaces
# e2 94 80 e2 94 -> 20 20 20 20 (spaces)
old_bytes = b'\xe2\x94\x80\xe2\x94'  # problematic bytes
new_bytes = b'    ' + b' '  # replacement

# Actually, let's just replace positions 1367-1369 with spaces
pos = 1367
# Replace 3 bytes at position 1367 with 3 spaces
data = data[:pos] + b'   ' + data[pos+3:]

# Now try to decode and check if it works
try:
    text = data.decode('utf-8')
    print('Now valid UTF-8')
    # Write back
    with open('AI_CONTEXT.md', 'w', encoding='utf-8') as f:
        f.write(text)
    print('Successfully rewrote AI_CONTEXT.md')
except UnicodeDecodeError as e:
    print(f'Still has error: {e}')
    # Try with errors replace
    text = data.decode('utf-8', errors='replace')
    with open('AI_CONTEXT.md', 'w', encoding='utf-8', errors='replace') as f:
        f.write(text)
    print('Rewrote with errors replace')
PYEOF