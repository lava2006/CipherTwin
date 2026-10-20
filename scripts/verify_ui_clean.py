import os
import sys

forbidden = [
    '\u2022',  # •
    '\u2192',  # →
    '\u2713',  # ✓
    '\u2715',  # ✕
    '\u26a0',  # ⚠
    '\u25b2',  # ▲
    '\u25bc',  # ▼
    '\u2014',  # —
    '\u2013',  # –
    '\u2026',  # …
    '\u00e2',  # â (mojibake)
    '\u00ce',  # Î (mojibake)
]

matches = []
for root, dirs, files in os.walk('frontend/src'):
    for f in files:
        if f.endswith(('.tsx', '.ts')):
            path = os.path.join(root, f)
            with open(path, 'r', encoding='utf-8', errors='ignore') as fp:
                for idx, line in enumerate(fp, 1):
                    for char in forbidden:
                        if char in line:
                            matches.append(f"{path}:{idx}: {line.strip()}")
                            break

print(f"TOTAL_SPECIALS_REMAINING: {len(matches)}")
for m in matches:
    print(m)

if len(matches) > 0:
    sys.exit(1)
print("SUCCESS: 0 forbidden characters found in frontend/src!")
