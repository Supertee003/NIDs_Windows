#!/usr/bin/env python3
"""Fix Aegis Bridge C++ banner for better visual appearance."""

with open('D:\\NIDs_Windows\\bridge\\aegis_bridge_main.cpp', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Keep lines 1-205 (before the banner section)
new_lines = lines[:205]

# Add the improved banner with ANSI colors
banner_lines = [
    '    const char* RST = "\\x1b[0m";\n',
    '    const char* BLD = "\\x1b[1m";\n',
    '    const char* CYN = "\\x1b[96m";\n',
    '    const char* GRN = "\\x1b[92m";\n',
    '    const char* YEL = "\\x1b[93m";\n',
    '    const char* DIM = "\\x1b[2m";\n',
    '\n',
    '    fprintf(stdout, "\\n");\n',
    '    fprintf(stdout, "%s╔════════════════════════════════════════════════════════════╗%s\\n", CYN, RST);\n',
    '    fprintf(stdout, "%s║%s %sAEGIS NIDS — IPC Bridge (C++)%s %s v2.0 %s                %s║%s\\n", CYN, RST, BLD, RST, DIM, RST, CYN, RST);\n',
    '    fprintf(stdout, "%s║%s %sMulti-Language Hybrid Architecture — Event Queue Hub%s  %s║%s\\n", CYN, RST, DIM, RST, CYN, RST);\n',
    '    fprintf(stdout, "%s╠════════════════════════════════════════════════════════════╣%s\\n", CYN, RST);\n',
    '    fprintf(stdout, "%s║%s %sZig Core%s · %sPython Brain%s · %sRust Shield%s · %sGo Nose%s  %s║%s\\n", CYN, RST, GRN, RST, GRN, RST, GRN, RST, GRN, RST, CYN, RST);\n',
    '    fprintf(stdout, "%s╚═════════════════════════════════════════════════════════════╝%s\\n", CYN, RST);\n',
    '\n',
]

new_lines.extend(banner_lines)

# Add the rest of the file from original line 222 onwards (index 221)
new_lines.extend(lines[221:])

with open('D:\\NIDs_Windows\\bridge\\aegis_bridge_main.cpp', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print('Bridge banner updated successfully')