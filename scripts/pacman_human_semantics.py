#!/usr/bin/env python3
"""Generate the fail-closed Pac-Man human-semantic documentation layer.

This script deliberately keeps byte/reconstruction reference independent from semantic
completion.  It consumes the already-certified release tree plus PacRipper's native
family manifests, maps every canonical instruction to exactly one recovered family,
and emits auditable semantic catalogs and annotations.

Created by Jacob Hodgkins
"""
from __future__ import annotations
import argparse, csv, hashlib, json, re, shutil
from collections import Counter, defaultdict
from pathlib import Path

HEX_RE=re.compile(r"0x([0-9A-Fa-f]{1,4})")

def h4(v:int)->str: return f"${v:04X}"
def pcs_from(s:str): return [int(x,16) for x in HEX_RE.findall(s)]
def cpp_unescape(s:str)->str:
    return bytes(s, 'utf-8').decode('unicode_escape')
def snake(name:str)->str:
    s=re.sub(r'(?<=[a-z0-9])(?=[A-Z])','_',name)
    s=re.sub(r'(?<=[A-Z])(?=[A-Z][a-z])','_',s)
    s=re.sub(r'[^A-Za-z0-9]+','_',s).strip('_').lower()
    return s

SJASMPLUS_LABEL_MAX=64

def semantic_asm_label(role:str, stable_id:str)->str:
    """Return a deterministic SjASMPlus-safe semantic family label.

    SjASMPlus 1.24.0 accepts labels up to 64 characters.  Keep readable labels
    unchanged when possible; only overlong labels are shortened and receive a
    stable hash suffix so the shortening cannot silently create a collision.
    """
    base='sem_'+snake(role)
    if len(base)<=SJASMPLUS_LABEL_MAX:
        return base
    suffix='_'+hashlib.sha256((stable_id+'\0'+role).encode('utf-8')).hexdigest()[:8]
    stem=base[:SJASMPLUS_LABEL_MAX-len(suffix)].rstrip('_')
    return stem+suffix

def words(name:str)->str:
    s=re.sub(r'(?<=[a-z0-9])(?=[A-Z])',' ',name)
    s=re.sub(r'(?<=[A-Z])(?=[A-Z][a-z])',' ',s)
    return s.replace('_',' ').strip()

def all_families(src:Path):
    reference=src/'semantic/family_semantics.json'
    if not reference.exists():
        raise RuntimeError(f'missing PacRipper semantic family reference: {reference}')
    rows=json.loads(reference.read_text(encoding='utf-8'))
    records=[]
    for row in rows:
        records.append(dict(
            stable_id=str(row['stable_id']), family=str(row['family']),
            entry=int(row['entry']), pcs=[int(x) for x in row['pcs']], evidence=str(row.get('evidence',''))
        ))
    return records

def load_code_overrides(src:Path):
    p=src/'semantic/code_semantic_overrides.csv'
    if not p.exists(): return {}
    with p.open(newline='') as f:
        rows=list(csv.DictReader(f))
    out={}
    for r in rows:
        sid=r['stable_id'].strip()
        if not sid: continue
        if sid in out: raise RuntimeError(f'duplicate code semantic override {sid}')
        out[sid]=r
    return out

def load_data_overrides(src:Path):
    p=src/'semantic/data_semantic_overrides.csv'
    if not p.exists(): return {}
    with p.open(newline='') as f:
        rows=list(csv.DictReader(f))
    out={}
    for r in rows:
        key=(int(r['start_address'][1:],16),int(r['end_address_inclusive'][1:],16)+1)
        if key in out: raise RuntimeError(f'duplicate data semantic override {key}')
        out[key]=r
    return out

GENERIC_EXACT_PREFIXES=(
    'SystemRootIsland','UpdateRoutine','ColdMode','ColdState','ColdMainDispatch',
    'ColdTaskDispatch','Utility23','Utility24'
)
GENERIC_NAMES={
    'CallHelper15B4','CallHelper15B7','CallHelper15BA','Helper15E6','Helper162D','Helper1652',
    'MainHelperFront02FD',
}

def raw_family_role(family:str)->str:
    s=re.sub(r'(?<=[a-z0-9])(?=[A-Z])',' ',family)
    s=re.sub(r'(?<=[A-Z])(?=[A-Z][a-z])',' ',s)
    return ' '.join(s.replace('_',' ').split())

def clean_public_evidence(text:str)->str:
    """Remove internal development-stage terminology from public evidence text."""
    t=' '.join((text or '').split())
    t=t.replace('transitional neighbor', 'adjacent routine')
    t=t.replace('transitional frontier', 'verified boundary')
    t=t.replace('already-native', 'already recovered').replace('already native', 'already recovered')
    t=t.replace('native CALL seam', 'verified CALL path').replace('native call seam', 'verified CALL path')
    t=t.replace('native $', 'recovered $')
    t=re.sub(r'\s+([,.;:])', r'\1', t)
    t=re.sub(r';\s*;', ';', t)
    return t.strip(' ;')

def role_quality_issue(family:str, role:str)->str:
    """Return a fail-closed reason when a public role is still recovery scaffolding.

    Human-semantic COMPLETE requires a behavioral/hardware/gameplay role, not merely a
    camel-case family name, address suffix, call seam, or cold/system-root placeholder.
    """
    role=' '.join((role or '').split())
    if not role:
        return 'empty human role'
    low=role.lower()
    if re.search(r'\bcold\b',low):
        return 'contains legacy Cold placeholder terminology'
    if 'systemrootisland' in re.sub(r'[^a-z0-9]','',low) or 'legacyinterruptlatchisland' in re.sub(r'[^a-z0-9]','',low):
        return 'contains structural island terminology'
    if re.match(r'^(?:call|return|jump continuation|call continuation|output branch|alternate branch|output gate)\b',role,re.I):
        return 'describes only a control-flow seam rather than behavior'
    if re.fullmatch(r'(?:helper|routine|handler|call|return|continuation|dispatch|state|mode|motion|coordinate)(?:\s+\w+)?',role,re.I):
        return 'too generic to identify human-visible behavior'
    raw=raw_family_role(family)
    if re.search(r'(?:_)?[0-9A-F]{4}$',family,re.I):
        if re.sub(r'[^a-z0-9]','',role.lower())==re.sub(r'[^a-z0-9]','',raw.lower()):
            return 'unchanged address-suffixed recovery family name'
    # Catch the exact visual artifacts that motivated the stricter audit, e.g. "Call1490"
    # or "Coordinate Primary141 F", without rejecting legitimate protocol names like RST 20.
    compact=re.sub(r'[^A-Za-z0-9]','',role)
    if re.search(r'(?:Call|Return|Helper|Cold|Coordinate|Motion)[0-9A-F]{4}$',compact,re.I):
        return 'address-derived structural role'
    return ''

def semantic_status(family:str,evidence:str):
    # Fail closed: names that identify only topology/address, without gameplay/hardware role,
    # are explicitly unfinished even though native semantic equivalence is proven.
    if family in GENERIC_NAMES: return 'PENDING'
    if family.startswith(GENERIC_EXACT_PREFIXES): return 'PENDING'
    if re.fullmatch(r'(?:Cold)?(?:Flag|Counter|Timer|Scan|Fill|SetupCopy)\w*?[0-9A-F]{4}',family): return 'PENDING'
    if re.fullmatch(r'Utility(?:Dispatch|Increment|Noop).*',family):
        # These names do describe their exact generic utility operation, so they count.
        return 'COMPLETE'
    if re.fullmatch(r'.*(?:Call)?Helper[0-9A-F]{4}',family) and not any(k in family for k in ('Coin','Score','Tile','Label','Blank','Rectangle')):
        return 'PENDING'
    if 'system-root-reachable canonical' in evidence.lower() and family.startswith('SystemRoot'):
        return 'PENDING'
    return 'COMPLETE'

def subsystem(family:str,evidence:str):
    t=(family+' '+evidence).lower()
    groups=[
      ('interrupt/startup',('interrupt','startup','checksum','watchdog','reset')),
      ('coin/credit/session',('coin','credit','start1','start2','player','session','lives','freeplay')),
      ('maze/tile/collision',('maze','tile','collision','boardclear','rectangle')),
      ('score/fruit/hud',('score','fruit','bonus','hud','digit')),
      ('intermission/attract',('intermission','attract','cutscene')),
      ('actor/ghost/motion',('actor','ghost','blinky','pinky','inky','clyde','motion','coordinate','sprite')),
      ('scheduler/task',('scheduler','task','queue','command','dispatch')),
      ('video/display',('video','screen','label','display','blank','render','color')),
      ('audio',('audio','sound','music','waveform')),
      ('game-state/control',('state','mode','main','update')),
    ]
    for name,keys in groups:
        if any(k in t for k in keys): return name
    return 'utility/other'

def load_instruction_ledger(rel:Path):
    with (rel/'program/instruction_ledger.csv').open(newline='') as f:
        rows=list(csv.DictReader(f))
    for r in rows: r['_pc']=int(r['pc'][1:],16)
    return rows

def load_data_spans(rel:Path):
    with (rel/'program/reconstruction_ledger.csv').open(newline='') as f: rows=list(csv.DictReader(f))
    spans=[]; cur=None
    for r in rows:
        if r['owner_kind']=='CanonicalInstruction': continue
        a=int(r['address'][1:],16); key=(r['owner_kind'],r['source_id'])
        if cur and cur['key']==key and a==cur['end']:
            cur['rows'].append(r);cur['end']=a+1
        else:
            if cur: spans.append(cur)
            cur={'key':key,'start':a,'end':a+1,'rows':[r]}
    if cur: spans.append(cur)
    return spans

def split_spans_for_overrides(spans, overrides):
    """Split coarse variant data ownership spans at certified semantic override boundaries.
    Puckman shares the same address-space data topology even when its variant bytes make
    the low-level classifier coalesce adjacent data ownership records."""
    cuts=set()
    for start,end in overrides: cuts.add(start); cuts.add(end)
    out=[]
    for sp in spans:
        points=sorted(x for x in cuts if sp['start'] < x < sp['end'])
        if not points:
            out.append(sp); continue
        boundaries=[sp['start']]+points+[sp['end']]
        rows_by_addr={int(r['address'][1:],16):r for r in sp['rows']}
        for a,b in zip(boundaries,boundaries[1:]):
            rows=[rows_by_addr[x] for x in range(a,b) if x in rows_by_addr]
            if rows: out.append({'key':sp['key'],'start':a,'end':b,'rows':rows})
    return out


def data_semantics(span,pc_to_family,main_task_dispatch,delayed_dispatch,data_overrides):
    kind=span['key'][0]; r=span['rows'][0]; text=r['source_text']; details=''
    key=(span['start'],span['end'])
    ov=data_overrides.get(key)
    if ov:
        return ov.get('semantic_status','COMPLETE') or 'COMPLETE', ov['semantic_label'], ov['semantic_detail']
    status='PENDING'; label=''
    raw=[int(x['expected_byte'][1:],16) for x in span['rows']]
    if kind=='ProvenUnused':
        status='COMPLETE'; label='proven_unused_preserved_bytes'; details='Negative closure proves these bytes are not consumed as active program/data in the certified model.'
    elif kind=='CanonicalDataObject':
        label=snake(text); details='Canonical data object is structurally proven but still lacks a sufficiently specific gameplay-domain interpretation.'
    elif kind=='ClassifiedData':
        label='classified_rom_data'; details=f'Ownership is proven as {text}, but the payload meaning/fields remain human-semantic work.'
    elif kind=='InlinePayload':
        if text=='RST $20 inline dispatch table':
            targets=[raw[i]|(raw[i+1]<<8) for i in range(0,len(raw)-1,2)]
            desc=[]; all_known=bool(targets)
            for idx,t in enumerate(targets):
                fam=pc_to_family.get(t)
                if fam:
                    desc.append(f'index {idx} -> {h4(t)} {fam["human_role"]} ({fam["semantic_status"]})')
                    all_known &= fam['semantic_status']=='COMPLETE'
                else:
                    desc.append(f'index {idx} -> {h4(t)} unmapped-target'); all_known=False
            details='RST $20 little-endian dispatch table: '+'; '.join(desc)
            label='rst20_inline_dispatch_table'
            status='COMPLETE' if all_known else 'PENDING'
        elif text=='RST $28 inline arguments' and len(raw)==2:
            task,param=raw
            target=main_task_dispatch.get(task)
            fam=pc_to_family.get(target) if target is not None else None
            if fam and fam['semantic_status']=='COMPLETE':
                status='COMPLETE'; label='rst28_task_id_and_parameter'
                details=f'RST $28 queue arguments: task_id={task} -> {h4(target)} {fam["human_role"]}; parameter=${param:02X}. First byte selects the 32-entry main task table at $23A8; second byte is passed in B to the task.'
            else:
                label='rst28_inline_arguments'; details=f'RST $28 queue arguments decode to task_id={task}, parameter=${param:02X}, but task target semantics are not complete.'
        elif text=='RST $30 inline payload' and len(raw)==3:
            delay,command,param=raw
            target=delayed_dispatch.get(command)
            fam=pc_to_family.get(target) if target is not None else None
            if fam and fam['semantic_status']=='COMPLETE':
                status='COMPLETE'; label='rst30_delay_command_and_parameter'
                details=f'RST $30 delayed-command record: encoded_delay=${delay:02X} (class={(delay>>6)&3}, low6_count={delay&0x3F}), command_id={command} -> {h4(target)} {fam["human_role"]}; parameter=${param:02X}. Scheduler stores three bytes at $4C90 and dispatches command through the $0247 table when due.'
            else:
                label='rst30_inline_payload'; details=f'RST $30 record decodes as delay=${delay:02X}, command_id={command}, parameter=${param:02X}, but command target semantics are not complete.'
        elif text=='CALL $2BCD inline five-byte payload' and len(raw)==5:
            addr=raw[0]|(raw[1]<<8); color,length,rows=raw[2:]
            status='COMPLETE'; label='rectangle_color_fill_descriptor'
            details=f'Inline descriptor consumed by $2BCD: destination={h4(addr)}, color=${color:02X}, row_length={length}, row_count={rows}. This call colors the bottom HUD rows; independent same-address documentation confirms the five fields.'
        else:
            label=snake(text); details='Inline ownership is exact; payload semantics remain unresolved.'
    return status,label,details



def annotate_asm(rel:Path,families,data_rows):
    p=rel/'program'/('puckman.asm' if (rel/'program/puckman.asm').exists() else 'pacman.asm')
    lines=p.read_text().splitlines()
    by_entry={r['entry']:r for r in families}
    by_data={int(r['start_address'][1:],16):r for r in data_rows}
    out=[]; inserted_entries=set(); inserted_data=set()
    insn_rx=re.compile(r';\s*@INSN\s+\$([0-9A-Fa-f]{4})\s+BYTES=')
    data_rx=re.compile(r';\s*@DATA\s+\$([0-9A-Fa-f]{4})\s+OWNER=')
    for line in lines:
        mi=insn_rx.search(line)
        if mi:
            pc=int(mi.group(1),16)
            if pc in by_entry and pc not in inserted_entries:
                r=by_entry[pc]; inserted_entries.add(pc)
                out.append('')
                out.append(f'; @SEMANTIC-FAMILY {r["public_id"]} STATUS={r["semantic_status"]}')
                out.append(f'; role: {r["human_role"]}')
                out.append(f'; subsystem: {r["subsystem"]}')
                if r.get('public_evidence'): out.append(f'; evidence: {r["public_evidence"]}')
                if r['semantic_status']=='COMPLETE': out.append(semantic_asm_label(r['human_role'],r['stable_id'])+':')
                else: out.append('; Pending semantic documentation: behavior is recovered, but this routine requires a more specific public role description.')
        md=data_rx.search(line)
        if md:
            a=int(md.group(1),16)
            if a in by_data and a not in inserted_data:
                r=by_data[a]; inserted_data.add(a)
                out.append('')
                out.append(f'; @SEMANTIC-DATA {r["span_id"]} STATUS={r["semantic_status"]} RANGE={r["start_address"]}-{r["end_address_inclusive"]}')
                out.append(f'; role: {r["semantic_label"] or "pending_data_meaning"}')
                out.append(f'; detail: {r["semantic_detail"]}')
        out.append(line)
    p.write_text('\n'.join(out)+'\n')

def normalized_tree_hash(root:Path):
    h=hashlib.sha256()
    for p in sorted(x for x in root.rglob('*') if x.is_file()):
        rel=p.relative_to(root).as_posix()
        if rel=='verification/source_tree_sha256.txt': continue
        h.update(rel.encode());h.update(b'\0');h.update(p.read_bytes());h.update(b'\0')
    return h.hexdigest()

def write_hash_manifest(root:Path):
    # Match the existing release convention: omit the manifest itself and normalized tree hash.
    items=[]
    for p in sorted(x for x in root.rglob('*') if x.is_file()):
        rel=p.relative_to(root).as_posix()
        if rel in ('verification/hashes.txt','verification/source_tree_sha256.txt'): continue
        items.append(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}')
    (root/'verification/hashes.txt').write_text('\n'.join(items)+'\n')
    (root/'verification/source_tree_sha256.txt').write_text(normalized_tree_hash(root)+'\n')

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('source_project',type=Path)
    ap.add_argument('certified_release',type=Path)
    ap.add_argument('output',type=Path)
    args=ap.parse_args()
    if args.output.exists(): shutil.rmtree(args.output)
    shutil.copytree(args.certified_release,args.output)
    rel=args.output
    is_puckman=(rel/'program/puckman.asm').exists()
    game_title='Puckman' if is_puckman else 'Pac-Man'
    semantics_name='PUCKMAN_PROGRAM_SEMANTICS.md' if is_puckman else 'PACMAN_PROGRAM_SEMANTICS.md'
    families=all_families(args.source_project)
    code_overrides=load_code_overrides(args.source_project)
    data_overrides=load_data_overrides(args.source_project)
    inst=load_instruction_ledger(rel)
    ledger_pcs={r['_pc'] for r in inst}
    owner={}; overlaps=[]
    for rec in families:
        rec['semantic_status']=semantic_status(rec['family'],rec['evidence'])
        rec['human_role']=words(rec['family'])
        rec['subsystem']=subsystem(rec['family'],rec['evidence'])
        rec['semantic_evidence']=''
        if rec['stable_id'] in code_overrides:
            ov=code_overrides[rec['stable_id']]
            rec['semantic_status']=ov.get('semantic_status','COMPLETE') or 'COMPLETE'
            rec['human_role']=ov['human_role'].strip()
            rec['subsystem']=ov['subsystem'].strip() or subsystem(rec['human_role'],ov.get('semantic_evidence',''))
            rec['semantic_evidence']=ov.get('semantic_evidence','').strip()
        rec['role_quality_issue']=role_quality_issue(rec['family'],rec['human_role'])
        if rec['semantic_status']=='COMPLETE' and rec['role_quality_issue']:
            rec['semantic_status']='PENDING'
        for pc in rec['pcs']:
            if pc in owner: overlaps.append((pc,owner[pc]['stable_id'],rec['stable_id']))
            owner[pc]=rec
    missing=sorted(ledger_pcs-set(owner)); extra=sorted(set(owner)-ledger_pcs)
    if len(families)!=381 or len(ledger_pcs)!=5414 or overlaps or missing or extra:
        raise SystemExit(f'family denominator mismatch families={len(families)} ledger={len(ledger_pcs)} overlaps={len(overlaps)} missing={len(missing)} extra={len(extra)}')
    family_ids={r['stable_id'] for r in families}
    unknown_overrides=set(code_overrides)-family_ids
    if unknown_overrides: raise SystemExit(f'unknown code semantic override IDs: {sorted(unknown_overrides)}')
    for index, r in enumerate(families, 1):
        r['public_id']=f'FAMILY_{index:03d}'
        r['public_evidence']=clean_public_evidence(r.get('semantic_evidence') or r.get('evidence',''))
    complete_roles=[snake(r['human_role']) for r in families if r['semantic_status']=='COMPLETE']
    dup_roles=[x for x,c in Counter(complete_roles).items() if c>1]
    if dup_roles: raise SystemExit(f'duplicate complete semantic role(s): {dup_roles}')
    complete_labels=[semantic_asm_label(r['human_role'],r['stable_id']) for r in families if r['semantic_status']=='COMPLETE']
    dup_labels=[x for x,c in Counter(complete_labels).items() if c>1]
    if dup_labels: raise SystemExit(f'duplicate complete semantic ASM label(s): {dup_labels}')
    overlong_labels=[x for x in complete_labels if len(x)>SJASMPLUS_LABEL_MAX]
    if overlong_labels: raise SystemExit(f'overlong semantic ASM label(s): {overlong_labels}')
    prog=rel/'program'
    with (prog/'semantic_family_catalog.csv').open('w',newline='') as f:
        fields=['family_id','entry_pc','source_pc_count','source_pcs','subsystem','semantic_status','human_role','evidence','pending_reason']
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for r in families:
            w.writerow(dict(family_id=r['public_id'],entry_pc=h4(r['entry']),source_pc_count=len(r['pcs']),source_pcs=' '.join(h4(x) for x in r['pcs']),subsystem=r['subsystem'],semantic_status=r['semantic_status'],human_role=r['human_role'],evidence=r['public_evidence'],pending_reason='' if r['semantic_status']=='COMPLETE' else (r.get('role_quality_issue') or 'Behavior is recovered, but the public role still needs a more specific domain description.')))
    with (prog/'semantic_instruction_catalog.csv').open('w',newline='') as f:
        fields=['instruction_id','pc','mnemonic','operands','family_id','family_entry_pc','subsystem','semantic_status','human_role']
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for irow in inst:
            r=owner[irow['_pc']]
            w.writerow(dict(instruction_id=irow['id'],pc=irow['pc'],mnemonic=irow['mnemonic'],operands=irow['operands'],family_id=r['public_id'],family_entry_pc=h4(r['entry']),subsystem=r['subsystem'],semantic_status=r['semantic_status'],human_role=r['human_role']))
    spans=load_data_spans(rel)
    if is_puckman: spans=split_spans_for_overrides(spans,data_overrides)
    data_rows=[]
    by_start={s['start']:s for s in spans}
    def targets_from(start):
        sp=by_start.get(start)
        if not sp: return {}
        raw=[int(x['expected_byte'][1:],16) for x in sp['rows']]
        return {i//2:(raw[i]|(raw[i+1]<<8)) for i in range(0,len(raw)-1,2)}
    delayed_dispatch=targets_from(0x0247)
    main_task_dispatch=targets_from(0x23A8)
    pc_to_family=owner
    for i,s in enumerate(spans):
        st,label,detail=data_semantics(s,pc_to_family,main_task_dispatch,delayed_dispatch,data_overrides)
        r=s['rows'][0]
        data_rows.append(dict(span_id=f'DATA_{i:03d}',start_address=h4(s['start']),end_address_exclusive=h4(s['end']),end_address_inclusive=h4(s['end']-1),byte_count=s['end']-s['start'],owner_kind=s['key'][0],source_id=s['key'][1],source_text=r['source_text'],provenance='verified reconstruction ownership',semantic_status=st,semantic_label=label,semantic_detail=detail))
    with (prog/'semantic_data_catalog.csv').open('w',newline='') as f:
        fields=list(data_rows[0].keys());w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(data_rows)
    annotate_asm(rel,families,data_rows)
    famc=Counter(r['semantic_status'] for r in families); instc=Counter(owner[r['_pc']]['semantic_status'] for r in inst); datac=Counter(r['semantic_status'] for r in data_rows)
    data_bytes=Counter()
    for r in data_rows:data_bytes[r['semantic_status']]+=int(r['byte_count'])
    overall='COMPLETE' if famc['COMPLETE']==381 and datac['COMPLETE']==len(data_rows) else 'INCOMPLETE'
    coverage=(instc['COMPLETE']+data_bytes['COMPLETE'])/(len(inst)+sum(data_bytes.values()))*100.0
    cov=(prog/'HUMAN_SEMANTIC_COVERAGE.txt')
    cov.write_text('\n'.join([
      f'{game_title} Program Semantic Coverage',
      'Created by Jacob Hodgkins','',f'OVERALL_STATUS={overall}',
      'COMPLETION_RULE=COMPLETE requires 381/381 code families and every non-code span to have documented semantics.',
      f'CODE_FAMILIES_TOTAL={len(families)}',f'CODE_FAMILIES_COMPLETE={famc["COMPLETE"]}',f'CODE_FAMILIES_PENDING={famc["PENDING"]}',
      f'INSTRUCTIONS_TOTAL={len(inst)}',f'INSTRUCTIONS_IN_COMPLETE_FAMILIES={instc["COMPLETE"]}',f'INSTRUCTIONS_IN_PENDING_FAMILIES={instc["PENDING"]}',
      f'DATA_SPANS_TOTAL={len(data_rows)}',f'DATA_SPANS_COMPLETE={datac["COMPLETE"]}',f'DATA_SPANS_PENDING={datac["PENDING"]}',
      f'NONCODE_BYTES_TOTAL={sum(data_bytes.values())}',f'NONCODE_BYTES_COMPLETE={data_bytes["COMPLETE"]}',f'NONCODE_BYTES_PENDING={data_bytes["PENDING"]}',
      f'COMBINED_INSTRUCTION_PLUS_NONCODE_UNIT_COVERAGE_PERCENT={coverage:.6f}',
      'BYTE_RECONSTRUCTION_STATUS=UNCHANGED; semantic documentation is verified independently.','']) )
    bysub=defaultdict(lambda:Counter())
    for r in families:bysub[r['subsystem']][r['semantic_status']]+=1
    pending=[r for r in families if r['semantic_status']=='PENDING']
    md=[f'# {game_title} Program Human Semantics','', '**Created by Jacob Hodgkins**','',f'**Semantic documentation status: {overall}**','',
        'This documentation is separate from byte completeness. The program source reconstructs all 16,384 program bytes; this document records the identified role of each recovered code family and non-code span.','',
        '## Code denominator','',f'- Recovered native families: **381/381 structurally mapped**.',f'- Canonical instructions mapped exactly once: **5,414/5,414**.',f'- Human-semantic COMPLETE families: **{famc["COMPLETE"]}/381**.',f'- Instructions inside COMPLETE families: **{instc["COMPLETE"]}/5,414**.','',
        '## Subsystems','']
    for k in sorted(bysub): md.append(f'- {k}: {bysub[k]["COMPLETE"]} complete / {sum(bysub[k].values())} families')
    md += ['', '## Non-code denominator','',f'- Contiguous non-code ownership spans: **{len(data_rows)}**.',f'- Human-semantic COMPLETE spans: **{datac["COMPLETE"]}/{len(data_rows)}**.',f'- Human-semantic pending spans: **{datac["PENDING"]}/{len(data_rows)}**.','',
           '## Pending code families','']
    if pending:
        md.append('These are deliberately *not* promoted merely because behavior is mechanically recovered:')
        md.append('')
        for r in pending: md.append(f'- `{r["public_id"]}` `{h4(r["entry"])}` — {r["human_role"]} ({len(r["pcs"])} instructions)')
    else:
        md.append('**None. All 381 recovered code families satisfy the strict human-semantic role-quality gate.**')
    md += ['','## Verification','', 'Run `python3 verification/verify_human_semantics.py . --require-complete` to verify that every documented code family and non-code span remains complete.','']
    (prog/semantics_name).write_text('\n'.join(md))
    # Standalone verifier is copied from the source verification script.
    verifier=args.source_project/'scripts/verify_human_semantic_release.py'
    shutil.copy2(verifier,rel/'verification/verify_human_semantics.py')
    # Add a concise public semantic-documentation preamble.
    readme=rel/'README.md'; old=readme.read_text()
    pre=f'''# {game_title} Program Semantic Documentation

**Created by Jacob Hodgkins**

Semantic documentation status: **{overall}**. Code-family coverage is **{famc['COMPLETE']}/381** and non-code span coverage is **{datac['COMPLETE']}/{len(data_rows)}**. Run `verification/verify_human_semantics.py --require-complete` to reproduce this check.

See `program/{semantics_name}` and `program/HUMAN_SEMANTIC_COVERAGE.txt`.

---

'''
    readme.write_text(pre+old)
    meta={'overall_status':overall,'code_families_total':381,'code_families_complete':famc['COMPLETE'],'instructions_total':5414,'instructions_complete':instc['COMPLETE'],'data_spans_total':len(data_rows),'data_spans_complete':datac['COMPLETE'],'noncode_bytes_total':sum(data_bytes.values()),'noncode_bytes_complete':data_bytes['COMPLETE']}
    (rel/'verification/human_semantic_status.json').write_text(json.dumps(meta,indent=2,sort_keys=True)+'\n')
    write_hash_manifest(rel)
    print(json.dumps(meta,indent=2,sort_keys=True))

if __name__=='__main__': main()
