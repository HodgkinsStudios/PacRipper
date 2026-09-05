#!/usr/bin/env python3
"""Verify that the public PacRipper tree contains product-oriented naming only.

Ordinary verification result text such as uppercase PASS/FAIL is intentionally allowed.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {'.cpp','.h','.hpp','.md','.txt','.py','.csv','.json','.cbp','.workspace','.bat','.sh'}
TEXT_NAMES = {'Makefile'}

# Build sensitive search terms from fragments so this verifier does not contain
# the very legacy strings it is designed to detect.
RULES = [
    ('numbered development label', re.compile(r'\\bP' + r'ass(?:[- ]?\\d+|\\d+)')),
    ('lowercase numbered development label', re.compile(r'\\bp' + r'ass\\d+')),
    ('numbered coverage label', re.compile(r'\\bW' + r'ave\\d+')),
    ('legacy project name', re.compile(r'Arcade' + r'PacRip', re.I)),
    ('conversation marker', re.compile(r'\\bnext' + r'\\s+chat\\b', re.I)),
    ('transfer-workflow marker', re.compile(r'\\bhand' + r'off\\b', re.I)),
    ('progress-snapshot marker', re.compile(r'\\bcheck' + r'point\\b', re.I)),
    ('lettered development label', re.compile(r'\\bP' + r'hase(?:-[A-Z0-9]+|\\s+[A-D]\\b)')),
]
RAW_TERMS = [
    b'Arcade' + b'PacRip',
    b'P' + b'ass' + b'33',
    b'P' + b'ass' + b'55',
    b'W' + b'ave' + b'49',
]

def iter_files():
    for path in ROOT.rglob('*'):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if rel.parts and rel.parts[0] in {'obj'}:
            continue
        yield path, rel

def main() -> int:
    offenders=[]
    for path,rel in iter_files():
        name=str(rel)
        for label,rx in RULES:
            if rx.search(name):
                offenders.append(f'{rel}: filename: {label}')
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in TEXT_NAMES:
            try:text=path.read_text(encoding='utf-8')
            except UnicodeDecodeError: continue
            for line_no,line in enumerate(text.splitlines(),1):
                for label,rx in RULES:
                    if rx.search(line):
                        offenders.append(f'{rel}:{line_no}: {label}')
        elif rel.parts and rel.parts[0]=='bin':
            data=path.read_bytes()
            for term in RAW_TERMS:
                if term in data:
                    offenders.append(f'{rel}: embedded legacy marker')
    if offenders:
        print('PacRipper public naming verification: FAIL', file=sys.stderr)
        for item in offenders[:200]: print('  '+item, file=sys.stderr)
        return 1
    print('PacRipper public naming verification: PASS')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
