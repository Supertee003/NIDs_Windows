#!/usr/bin/env python3
import re

current_head = '688ab566d477105df5f868cee1571fbec77eedfd'

with open('AI_CONTEXT.md', 'r', errors='replace') as f:
    content = f.read()

# Replace the HEAD marker
old = '**HEAD:** `60c76fe61e2fc2cfc9e436fa001e2b0788f006f5`'
new = f'**HEAD:** `{current_head}`'

if old in content:
    content = content.replace(old, new)
    print('Replaced HEAD marker via string')
else:
    # Try bytes replacement
    old_bytes = '60c76fe61e2fc2cfc9e436fa001e2b0788f006f5'.encode()
    if old_bytes in content.encode('utf-8', errors='replace'):
        content = content.replace(old_bytes.decode(), current_head)
        print('Replaced HEAD marker via bytes')
    else:
        print('Could not find old HEAD marker')

with open('AI_CONTEXT.md', 'w', errors='replace') as f:
    f.write(content)
print('AI_CONTEXT.md updated')