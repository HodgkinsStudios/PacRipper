#!/usr/bin/env python3
"""Fail-closed consistency/completion verifier for the Pac-Man semantic release layer.
Created by Jacob Hodgkins
"""
import argparse,csv,json,re,sys
from collections import Counter
from pathlib import Path

def pc(s): return int(s[1:],16)

def _norm(s): return re.sub(r'[^a-z0-9]','',(s or '').lower())
def _raw_family_role(family):
    s=re.sub(r'(?<=[a-z0-9])(?=[A-Z])',' ',family)
    s=re.sub(r'(?<=[A-Z])(?=[A-Z][a-z])',' ',s)
    return ' '.join(s.replace('_',' ').split())
def role_quality_issue(family,role):
    role=' '.join((role or '').split())
    if not role:return 'empty human role'
    low=role.lower(); compact=re.sub(r'[^A-Za-z0-9]','',role)
    if re.search(r'\bcold\b',low):return 'legacy Cold placeholder terminology'
    if 'systemrootisland' in _norm(role) or 'legacyinterruptlatchisland' in _norm(role):return 'structural island terminology'
    if re.match(r'^(?:call|return|jump continuation|call continuation|output branch|alternate branch|output gate)\b',role,re.I):return 'control-flow seam only'
    if re.search(r'(?:_)?[0-9A-F]{4}$',family,re.I) and _norm(role)==_norm(_raw_family_role(family)):return 'unchanged address-suffixed recovery name'
    if re.search(r'(?:Call|Return|Helper|Cold|Coordinate|Motion)[0-9A-F]{4}$',compact,re.I):return 'address-derived structural role'
    return ''
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('release_root',nargs='?',default='.')
    ap.add_argument('--require-complete',action='store_true')
    args=ap.parse_args(); root=Path(args.release_root)
    prog=root/'program'
    fam=list(csv.DictReader((prog/'semantic_family_catalog.csv').open()))
    ins=list(csv.DictReader((prog/'semantic_instruction_catalog.csv').open()))
    data=list(csv.DictReader((prog/'semantic_data_catalog.csv').open()))
    canon=list(csv.DictReader((prog/'instruction_ledger.csv').open()))
    errors=[]
    if len(fam)!=381: errors.append(f'expected 381 families, got {len(fam)}')
    if len(ins)!=5414: errors.append(f'expected 5414 semantic instruction rows, got {len(ins)}')
    if len(canon)!=5414: errors.append(f'expected 5414 canonical instruction rows, got {len(canon)}')
    if len({r['family_id'] for r in fam})!=len(fam): errors.append('duplicate family IDs')
    canonpcs={r['pc'] for r in canon}; inspcs={r['pc'] for r in ins}
    if canonpcs!=inspcs: errors.append(f'instruction PC set mismatch missing={len(canonpcs-inspcs)} extra={len(inspcs-canonpcs)}')
    family_ids={r['family_id'] for r in fam}
    bad=[r for r in ins if r['family_id'] not in family_ids]
    if bad: errors.append(f'{len(bad)} instruction rows reference missing family')
    valid={'COMPLETE','PENDING'}
    if any(r['semantic_status'] not in valid for r in fam+data): errors.append('invalid semantic status')
    bad_roles=[(r['family_id'],r['human_role'],'generic public role') for r in fam if r['semantic_status']=='COMPLETE' and (not r['human_role'].strip() or re.match(r'^(?:helper|routine|handler)$', r['human_role'].strip(), re.I))]
    if bad_roles:
        errors.append(f'{len(bad_roles)} COMPLETE families still have structural/address-derived public roles')
        for sid,role,why in bad_roles[:20]: errors.append(f'{sid}: {role!r}: {why}')
    fcnt=Counter(r['semantic_status'] for r in fam); dcnt=Counter(r['semantic_status'] for r in data)
    icnt=Counter(r['semantic_status'] for r in ins)
    complete=fcnt['COMPLETE']==381 and dcnt['PENDING']==0 and len(data)>0
    asm_path=prog/('puckman.asm' if (prog/'puckman.asm').exists() else 'pacman.asm')
    asm=asm_path.read_text(errors='replace')
    entries=set(re.findall(r'@SEMANTIC-FAMILY\s+(FAMILY_\d+)',asm))
    if entries!=family_ids: errors.append(f'ASM semantic-family annotation mismatch missing={len(family_ids-entries)} extra={len(entries-family_ids)}')
    semantic_labels=re.findall(r'(?m)^(sem_[A-Za-z0-9_]+):\s*$',asm)
    if len(semantic_labels)!=len(set(semantic_labels)): errors.append('duplicate semantic ASM labels')
    overlong=[label for label in semantic_labels if len(label)>64]
    if overlong: errors.append(f'{len(overlong)} semantic ASM label(s) exceed SjASMPlus 64-character limit: {overlong[:5]}')
    print(('Puckman' if (prog/'puckman.asm').exists() else 'Pac-Man')+' human semantic verifier')
    print(f'families: {fcnt["COMPLETE"]}/381 complete; {fcnt["PENDING"]} pending')
    print(f'instructions: {icnt["COMPLETE"]}/5414 in complete families; {icnt["PENDING"]} pending')
    print(f'data spans: {dcnt["COMPLETE"]}/{len(data)} complete; {dcnt["PENDING"]} pending')
    print('documentation status:', 'COMPLETE' if complete else 'INCOMPLETE')
    if errors:
        print('CONSISTENCY: FAIL')
        for e in errors: print(' -',e)
        return 2
    print('CONSISTENCY: PASS')
    if args.require_complete and not complete:
        print('REQUIRE_COMPLETE: FAIL (semantic documentation is not 100% complete)')
        return 3
    if args.require_complete: print('REQUIRE_COMPLETE: PASS')
    return 0
if __name__=='__main__': sys.exit(main())
