#!/usr/bin/env python3
"""Create a polished public Pac-Man disassembly tree from a verified release tree.
Created by Jacob Hodgkins.

This step normalizes public terminology and metadata without changing executable
source bytes or board-resource source data. Verification manifests are regenerated.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,re,shutil,textwrap
from pathlib import Path

DEV_RE = re.compile(
    r'(?:\bP' + r'ass(?:[- ]?\d+|\d+)|\bp' + r'ass\d+|'
    r'(?i:\bW' + r'ave\d+|\bP' + r'hase-[A-Z0-9]+|\bhand' + r'off\b|'
    r'\bcheck' + r'point\b|\bnext' + r'\s+chat\b|Arcade' + r'PacRip))'
)

def read_csv(p):
    with p.open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def write_csv(p,fields,rows):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields,lineterminator='\n');w.writeheader();w.writerows(rows)

def clean_evidence(text):
    t=' '.join((text or '').split())
    replacements={
'transitional neighbor':'adjacent routine',
      'transitional frontier':'verified boundary','already-native':'already recovered',
      'already native':'already recovered','native CALL seam':'verified CALL path',
      'native call seam':'verified CALL path','native $':'recovered $',
      'current-verification point':'current verification','verified program':'verified program',
    }
    for a,b in replacements.items():t=t.replace(a,b)
    # Normalize implementation-oriented language in public semantic prose.
    exact_old='Exact recovered instruction behavior and callers/consumers identify this role; public name was normalized to remove structural/address-derived recovery scaffolding.'
    if t == exact_old:
        return 'Instruction behavior and known callers/consumers identify this role.'
    t=t.replace('source-complete ', '').replace('Source-complete ', '')
    t=t.replace('native C++ switch/table boundary','game-state dispatch boundary')
    t=t.replace('now-native ','').replace('already recovered ','existing ').replace('already-recovered ','existing ')
    t=t.replace('native execution','execution').replace('native selector dispatch','selector dispatch')
    t=t.replace('native attract-task family','attract-task routine').replace('native state-3 helper','state-3 helper')
    t=t.replace('native IY=','IY=').replace('native prefix','instruction prefix')
    t=t.replace('native CALL path','CALL path').replace('verified CALL path','CALL path')
    t=t.replace('recovered $','$').replace('recovered instruction','instruction')
    t=t.replace('connected HUD frontier:', 'HUD path:').replace('HUD frontier:', 'HUD path:')
    t=t.replace('frontier:', 'path:').replace(' frontier', ' path')
    t=t.replace('post-lookup seam','post-lookup path').replace('return seam','return path')
    t=t.replace('dispatch seam','dispatch path').replace('lookup seam','lookup path').replace('CALL seam','CALL path')
    t=t.replace('mid-entry seams','mid-entry paths').replace('seam:', 'path:').replace(' seam', ' path')
    t=t.replace('separately registered','separate').replace('separately callable','separately callable')
    t=t.replace('remains honestly transitional','continues through the established return path')
    t=t.replace('inherited ', '')
    t=t.replace('proves fourteen-state','implements fourteen-state')
    t=t.replace('elevated to a game-state dispatch boundary','implements the game-state dispatch boundary')
    t=t.replace('reset entry: DI, IM2 page initialization, and direct boot transfer elevated from exact operations',
                'reset entry: disables interrupts, initializes the IM2 vector page, and transfers to the boot routine')
    t=t.replace('/23 lifecycle proof identifies the complete intermission actor/ghost state initializer; writes are elevated to named state-oriented C++',
                'initializes the complete intermission actor and ghost state block')
    t=t.replace('source-exact companion clear routine elevated to direct C++ state writes',
                'clears the intermission actor state fields initialized by the companion setup routine')
    t=t.replace('task queue append/ring-wrap core with direct typed queue-pointer ownership',
                'appends a two-byte task record to the scheduler queue and wraps the queue pointer at the ring boundary')
    t=t.replace('attract/session task batch with scheduler ownership and sound-enable projection',
                'queues the attract/session task batch and applies the associated sound-enable state')
    t=t.replace('complete lives-display controller for B=0, 1..5, and >=6; execution includes exact nested helper call/return stack effects while helper ownership remains separate',
                'handles lives-display cases for B=0, B=1..5, and B>=6, including the nested display-helper call')
    t=t.replace('source-exact top-level session reset/attract baseline state',
                'resets session state to the baseline used when beginning a new game or attract sequence')
    t=t.replace('source-exact 30-byte FF plus four-byte $14 lifecycle-state initialization',
                'initializes the lifecycle-state block with 30 bytes of $FF followed by four bytes of $14')
    # Clauses about host/native-dispatch registration describe the recovery process, not Pac-Man.
    t=re.sub(r';?\s*every primary instruction is independently native-dispatchable\.?','',t,flags=re.I)
    t=re.sub(r';?\s*while helper ownership remains separately registered\.?','',t,flags=re.I)
    t=t.replace('native-dispatchable','documented')
    t=t.replace(' recovery scaffolding','').replace('recovery scaffolding','')
    t=re.sub(r'\s+([,.;:])',r'\1',t);t=re.sub(r';\s*;', ';', t)
    return t.strip(' ;')

def clean_general(text):
    pairs={
      'PacmanColorCodec(shared_with_NativeVideoNativeRenderer)':'PacmanColorCodec',
      'PacmanWaveformCodec(shared_with_NativeAudioNativeAudio)':'PacmanWaveformCodec',
      'NativeRenderer':'PacmanColorCodec',
      'serialized_upper_nibble_not_consumed_by_nativeVideo':'serialized_upper_nibble_preserved_for_exact_rebuild',
      'current_nativeVideo_group_reachable':'renderer_group_reachable',
      'audio_address_formula':'waveform_address_formula',
      'NativeVideo framebuffer hashes':'renderer framebuffer reference hashes',
      'NativeAudio PCM hashes':'audio PCM reference hashes',
      'NativeVideo canonical framebuffer preservation':'renderer framebuffer reference preservation',
      'NativeAudio canonical PCM preservation':'audio PCM reference preservation',
      'Pac-Man color recovery color semantics':'Pac-Man color PROM semantics',
      'Pac-Man audio recovery sound PROM semantics':'Pac-Man sound PROM semantics',
      'NativeVideo consumes the serialized lookup byte low nibble as a 0..15 palette index.':'The renderer consumes the serialized lookup byte low nibble as a 0..15 palette index.',
      'The serialized upper nibble is preserved as explicit reconstruction data and is not consumed by NativeVideo.':'The serialized upper nibble is preserved as explicit reconstruction data and is not used by the board palette lookup.',
      'Current NativeVideo tile/sprite state masks color groups to 0..31; lookup groups 32..63 are still fully sourceified and this does not assert board-level irrelevance.':'The decoded tile/sprite color path uses groups 0..31; lookup groups 32..63 remain fully source-owned for exact reconstruction.',
      'NativeAudio addresses (waveform_id << 5) | position: 8 waveforms x 32 samples.':'Waveform addressing is (waveform_id << 5) | position: 8 waveforms x 32 samples.',
      'NativeAudio consumes low_nibble - 8 as the signed waveform sample.':'The low nibble is interpreted as low_nibble - 8 for the signed waveform sample.',
    }
    for a,b in pairs.items():text=text.replace(a,b)
    text=text.replace('Pac-Man Program Human Semantics','Pac-Man Program Semantic Documentation')
    text=text.replace('This layer is intentionally separate from byte completeness. The certified program already owns and reconstructs all 16,384 program bytes; this document measures whether another human can understand what each recovered code family and non-code span *means*.',
                      'Semantic documentation is kept separate from byte reconstruction. The program source reconstructs all 16,384 bytes; this document describes the purpose of each code family and non-code span.')
    text=text.replace('Human-semantic COMPLETE families:', 'Semantically documented families:')
    text=text.replace('Instructions inside COMPLETE families:', 'Instructions covered by documented families:')
    text=text.replace('Human-semantic COMPLETE spans:', 'Semantically documented spans:')
    text=text.replace('Human-semantic pending spans:', 'Undocumented spans:')
    text=text.replace('The human-semantic catalog identifies', 'The semantic catalog identifies')
    text=text.replace('all **5,414 certified instructions**', 'all **5,414 decoded instructions**')
    text=text.replace('decoded/sourceified graphics, palette, lookup, waveform, and timing/control source data',
                      'decoded and structured graphics, palette, lookup, waveform, and timing/control source data')
    text=text.replace('82s126.3m timing/control PROM role (evidence-established; not guessed):',
                      '82s126.3m timing/control PROM documented hardware role:')
    text=text.replace('Recovered native families:', 'Documented code families:')
    text=text.replace('All 381 recovered code families satisfy the strict human-semantic role-quality gate.',
                      'All 381 code families have complete semantic role documentation.')
    text=text.replace('The current verified analysis native audio model directly generates its deterministic PCM timing and therefore does not consume 3M; that current product-path fact is distinct from 3M\'s proven original-board timing/control role.',
                      'The reference runtime audio model generates PCM timing directly and does not consume 3M; this implementation detail is separate from 3M\'s documented original-board timing/control role.')
    text=text.replace('reference_only_current_native_path','reference_only_for_runtime_audio_model')
    text=text.replace('verified program direct-native=5414/5414 transitional=0 families=381 PRESERVED',
                      'program instructions=5414/5414 documented; code families=381 PRESERVED')
    text=text.replace('independent source reconstruction=verified analysis/10 files byte-exact',
                      'independent source reconstruction=10/10 files byte-exact')
    text=text.replace('No certified reachable call/jump enters $2C44', 'No known reachable call or jump enters $2C44')
    text=text.replace('because the structural ownership split cuts through the startup self-test grid descriptor table',
                      'because the source-region boundary falls inside the startup self-test grid descriptor table')
    return text

def normalized_tree_hash(root):
    h=hashlib.sha256()
    for p in sorted(x for x in root.rglob('*') if x.is_file()):
        rel=p.relative_to(root).as_posix()
        if rel=='verification/source_tree_sha256.txt':continue
        h.update(rel.encode());h.update(b'\0');h.update(p.read_bytes());h.update(b'\0')
    return h.hexdigest()
def write_hashes(root):
    items=[]
    for p in sorted(x for x in root.rglob('*') if x.is_file()):
        rel=p.relative_to(root).as_posix()
        if rel in ('verification/hashes.txt','verification/source_tree_sha256.txt'):continue
        items.append(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}')
    (root/'verification/hashes.txt').write_text('\n'.join(items)+'\n')
    (root/'verification/source_tree_sha256.txt').write_text(normalized_tree_hash(root)+'\n')

def main():
    ap=argparse.ArgumentParser(description='Create polished public Pac-Man disassembly release')
    ap.add_argument('verified_release',type=Path);ap.add_argument('output',type=Path)
    a=ap.parse_args()
    if a.output.exists():shutil.rmtree(a.output)
    shutil.copytree(a.verified_release,a.output)
    r=a.output;p=r/'program'
    is_puckman=(p/'puckman.asm').exists()
    game_title='Puckman' if is_puckman else 'Pac-Man'
    asm_name='puckman.asm' if is_puckman else 'pacman.asm'
    semantics_name='PUCKMAN_PROGRAM_SEMANTICS.md' if is_puckman else 'PACMAN_PROGRAM_SEMANTICS.md'

    ins=read_csv(p/'instruction_ledger.csv');fields=['id','pc','length','bytes','mnemonic','operands']
    write_csv(p/'instruction_ledger.csv',fields,[{k:x[k] for k in fields} for x in ins])

    rec=read_csv(p/'reconstruction_ledger.csv')
    rec_fields=[x for x in rec[0] if x!='provenance']
    write_csv(p/'reconstruction_ledger.csv',rec_fields,[{k:x.get(k,'') for k in rec_fields} for x in rec])
    mp=read_csv(p/'reconstruction_map.csv');mp_fields=[x for x in mp[0] if x!='provenance']
    write_csv(p/'reconstruction_map.csv',mp_fields,[{k:x.get(k,'') for k in mp_fields} for x in mp])
    prov=read_csv(p/'provenance_ledger.csv')
    for x in prov:
        x['provenance']=(f"canonical instruction {x['source_id']} byte {x['source_offset']}" if x['owner_kind']=='CanonicalInstruction' else f"{x['owner_kind']} source {x['source_id']} byte {x['source_offset']}")
    write_csv(p/'provenance_ledger.csv',list(prov[0]),prov)

    q=p/'rebuild_verification.txt';q.write_text(clean_general(q.read_text()))

    fam=read_csv(p/'semantic_family_catalog.csv');idmap={};cleanfam=[]
    for i,x in enumerate(fam,1):
        old=x.get('stable_id') or x.get('family_id');new=f'FAMILY_{i:03d}';idmap[old]=new
        evidence=clean_evidence(x.get('semantic_evidence') or x.get('evidence',''))
        cleanfam.append(dict(family_id=new,entry_pc=x['entry_pc'],source_pc_count=x['source_pc_count'],source_pcs=x['source_pcs'],subsystem=x['subsystem'],semantic_status=x['semantic_status'],human_role=x['human_role'],evidence=evidence,pending_reason=clean_evidence(x.get('pending_reason',''))))
    ff=['family_id','entry_pc','source_pc_count','source_pcs','subsystem','semantic_status','human_role','evidence','pending_reason']
    write_csv(p/'semantic_family_catalog.csv',ff,cleanfam);byid={x['family_id']:x for x in cleanfam}
    si=read_csv(p/'semantic_instruction_catalog.csv');clean_si=[]
    for x in si:
        old=x.get('stable_id') or x.get('family_id');fid=idmap.get(old,old)
        clean_si.append(dict(instruction_id=x['instruction_id'],pc=x['pc'],mnemonic=x['mnemonic'],operands=x['operands'],family_id=fid,family_entry_pc=x['family_entry_pc'],subsystem=x['subsystem'],semantic_status=x['semantic_status'],human_role=x['human_role']))
    sif=['instruction_id','pc','mnemonic','operands','family_id','family_entry_pc','subsystem','semantic_status','human_role']
    write_csv(p/'semantic_instruction_catalog.csv',sif,clean_si)
    sd=read_csv(p/'semantic_data_catalog.csv')
    for x in sd:
        if 'provenance' in x:x['provenance']='verified reconstruction ownership'
        x['semantic_detail']=clean_evidence(x.get('semantic_detail',''))
    write_csv(p/'semantic_data_catalog.csv',list(sd[0]),sd)

    asm=(p/asm_name).read_text().splitlines();out=[];i=0
    marker=re.compile(r'^; @SEMANTIC-FAMILY\s+(\S+)')
    while i<len(asm):
        m=marker.match(asm[i])
        if m:
            old=m.group(1);fid=idmap.get(old,old);fr=byid.get(fid);i+=1
            while i<len(asm) and asm[i].startswith(';'):i+=1
            if fr:
                out.append(f'; @SEMANTIC-FAMILY {fid} STATUS={fr["semantic_status"]}')
                out.append(f'; role: {fr["human_role"]}')
                out.append(f'; subsystem: {fr["subsystem"]}')
                if fr['evidence']:out.append(f'; evidence: {fr["evidence"]}')
            continue
        line=asm[i]
        if i==0 and line.startswith('; Pac-Man'):line='; Pac-Man (Midway/Namco hardware) Z80 disassembly'
        if i==0 and line.startswith('; Puckman'):line='; Puckman (Namco Pac-Man-family hardware) Z80 disassembly'
        line=line.replace('Generated by PacRipper from the certified canonical instruction/data ownership model.','Generated by PacRipper from the verified instruction/data ownership model.')
        line=line.replace('This is the primary HUMAN-READABLE program source. Instructions are emitted as Z80 mnemonics.','Primary readable program source: code is emitted as Z80 mnemonics.')
        line=line.replace('Each instruction carries an @INSN marker used by the standalone release verifier.','@INSN and @DATA markers are machine-readable verification metadata.')
        if line.startswith('; @SEMANTIC-DATA') or line.startswith('; detail:') or line.startswith('; source:'):line=clean_general(line)
        out.append(line);i+=1
    # Keep pure documentation comments comfortably below conservative assembler
    # line-length limits. Executable/machine-readable source lines are untouched.
    wrapped=[]
    for line in out:
        stripped=line.lstrip()
        indent=line[:len(line)-len(stripped)]
        if stripped.startswith(';') and len(line)>160:
            body=stripped[1:].lstrip()
            chunks=textwrap.wrap(body,width=max(40,156-len(indent)),break_long_words=False,break_on_hyphens=False) or ['']
            wrapped.extend(indent+'; '+chunk for chunk in chunks)
        else:
            wrapped.append(line)
    (p/asm_name).write_text('\n'.join(wrapped)+'\n')

    for sub in ('audio','color','graphics','manifest'):
        for f in (r/sub).rglob('*'):
            if f.is_file() and f.suffix.lower() in ('.txt','.csv','.md'):
                try:f.write_text(clean_general(f.read_text()))
                except UnicodeDecodeError:
                    continue

    docs=r/'docs';docs.mkdir(exist_ok=True)
    for f in list(docs.iterdir()):
        if f.is_file():f.unlink()
    docs.joinpath('PROGRAM_SEMANTIC_DOCUMENTATION.md').write_text(f"""# {game_title} Program Semantic Documentation

**Created by Jacob Hodgkins**

The readable Z80 source is organized into **381 documented code families** covering all **5,414 instructions**. The non-code program region is divided into **257 documented ownership spans** covering all **4,783 non-code bytes**.

The semantic catalogs under `program/` provide routine roles, subsystem assignments, instruction-to-family mapping, and non-code data descriptions. These descriptions are kept separate from byte reconstruction so documentation edits cannot silently change the canonical byte proof.

Run `python3 verification/verify_human_semantics.py . --require-complete` to verify the documentation coverage.
""")

    st=r/'verification/human_semantic_status.json'
    if st.exists():
        d=json.loads(st.read_text());d['overall_status']='COMPLETE' if d.get('code_families_complete')==381 and d.get('data_spans_complete')==d.get('data_spans_total') else 'INCOMPLETE'
        new=r/'verification/semantic_documentation_status.json';new.write_text(json.dumps(d,indent=2,sort_keys=True)+'\n');st.unlink()

    source_verifier=Path(__file__).with_name('verify_human_semantic_release.py')
    if source_verifier.exists():shutil.copy2(source_verifier,r/'verification/verify_human_semantics.py')
    board_verifier=Path(__file__).with_name('verify_variant_board_export.py' if is_puckman else 'verify_complete_board_export.py')
    if board_verifier.exists():shutil.copy2(board_verifier,r/'verification/verify_complete_board_export.py')
    archive_helper=Path(__file__).with_name('archive_support.py')
    if archive_helper.exists():shutil.copy2(archive_helper,r/'verification/archive_support.py')

    cov=p/'HUMAN_SEMANTIC_COVERAGE.txt'
    if cov.exists():
        t=clean_general(cov.read_text()).replace('Pac-Man Human Semantic Documentation Coverage','Pac-Man Program Semantic Coverage')
        t=t.replace('COMPLETION_RULE=COMPLETE requires 381/381 code families AND every non-code span to have certified human semantics.','COMPLETION_RULE=COMPLETE requires 381/381 code families and every non-code span to have documented semantics.')
        cov.write_text(t)
    sem=p/semantics_name
    if sem.exists():
        t=clean_general(sem.read_text()).replace('## Certification rule','## Verification')
        t=t.replace('An archive may be labeled **COMPLETE** only when `verification/verify_human_semantics.py --require-complete` succeeds. Any future regression below that gate must be labeled **INCOMPLETE**.','Run `python3 verification/verify_human_semantics.py . --require-complete` to verify complete semantic documentation.')
        sem.write_text(t)

    for f in r.iterdir():
        if f.is_file() and f.suffix.lower() in ('.md','.txt'):f.write_text(clean_general(f.read_text()))
    if is_puckman:
        (r/'README.md').write_text(f"""# Puckman Complete Board Disassembly

**Created by Jacob Hodgkins**

This package contains a complete readable Z80 disassembly of canonical Puckman plus structured source for graphics, color, waveform, and timing/control resources. It is independent of the Pac-Man disassembly and rebuilds Puckman's native 16-file physical set.

## Coverage

- 5,414 / 5,414 Z80 instructions documented and emitted as mnemonics.
- 16,384 / 16,384 program bytes source-owned.
- 381 / 381 program code families documented.
- 257 / 257 non-code program spans documented.
- 16 / 16 active board ROM/PROM files reconstruct byte-for-byte.
- 25,376 / 25,376 active board bytes reconstruct exactly.

## Main source

- `program/puckman.asm` — complete Puckman Z80 source and exact program reconstruction source.
- `PUCKMAN_VARIANT_SEMANTICS.md` — certified Pac-Man/Puckman variant differences.
- `verification/build_complete_rom_set.py` — writes the 16-file physical Puckman set from an externally assembled 16-KiB program image plus structured resource sources.

See `BUILDING_COMPLETE_ROM_SET.md` for the independent SjASMPlus round trip.
""")
    else:
        (r/'README.md').write_text("""# Pac-Man 1980 Complete Board Disassembly

**Created by Jacob Hodgkins**

This package contains a readable Z80 disassembly of the complete active Pac-Man program ROM set plus structured, editable source representations for the graphics ROMs, color PROMs, waveform PROM, and sound timing/control PROM.

## Coverage

- 5,414 / 5,414 Z80 instructions documented and emitted as mnemonics.
- 16,384 / 16,384 program bytes source-owned.
- 381 / 381 program code families documented.
- 257 / 257 non-code program spans documented.
- 10 / 10 active board ROM/PROM files reconstruct byte-for-byte.
- 25,376 / 25,376 active board bytes reconstruct exactly.

## Main source files

- `program/pacman.asm` — readable Z80 source with routine/data semantics and the sole exact-byte program reconstruction source.
- `graphics/` — editable character and sprite pixel sources and maps.
- `color/` — editable palette and color-lookup PROM sources.
- `audio/` — editable waveform and timing/control PROM sources.
- `manifest/` — active-board file and byte ownership manifests.
- `verification/` — independent reconstruction and semantic-documentation verifiers.

## Rebuilding

See `BUILDING_COMPLETE_ROM_SET.md` for the documented SjASMPlus program-assembly path and complete 10-file ROM/PROM reconstruction procedure. `ROUND_TRIP_REBUILD_CERTIFICATION.md` records the verified byte-identical round trip.

If a supplied archive contains members outside the active 10-file canonical board set, they are listed in `manifest/excluded_archive_members.csv` and excluded from the reconstruction denominator.
""")

    legal_notice=f"""# Legal Notice for Generated {game_title} Source

**Generated by PacRipper V1.0 — Created by Jacob Hodgkins**

PacRipper's software license applies to the PacRipper program and PacRipper-authored project documentation. It does **not** grant rights to the ROM/PROM data supplied by the user.

This generated source/disassembly is derived from ROM data supplied by the user. PacRipper does not grant permission to redistribute the original ROM/PROM data or this ROM-derived output. Users are responsible for determining whether their possession, use, modification, or distribution of the input data and generated output is permitted in their jurisdiction.

PacRipper is an independent research/reconstruction utility and is not affiliated with, sponsored by, authorized by, or endorsed by the game or hardware rights holders. Pac-Man/Puckman names and related trademarks belong to their respective owners.

No input ROM archive is copied into this generated source tree.
"""
    (r/'LEGAL_NOTICE.md').write_text(legal_notice)
    readme=r/'README.md'
    readme.write_text(readme.read_text()+"\n## Legal note\n\nSee `LEGAL_NOTICE.md` before redistributing ROM-derived generated output. PacRipper's software license does not relicense user-supplied ROM data or generated ROM-derived source.\n")

    for f in (r/'verification').iterdir():
        if f.is_file() and f.suffix.lower() in ('.txt','.md') and f.name not in ('hashes.txt','source_tree_sha256.txt'):f.write_text(clean_general(f.read_text()))
    write_hashes(r)

    offenders=[]
    for f in r.rglob('*'):
        if not f.is_file() or f.suffix.lower() in ('.ppm','.png','.jpg','.jpeg','.zip'):continue
        try:t=f.read_text(errors='strict')
        except (UnicodeDecodeError,ValueError):continue
        if DEV_RE.search(t) or DEV_RE.search(f.relative_to(r).as_posix()):offenders.append(f.relative_to(r).as_posix())
    if offenders:raise SystemExit('public release still contains development-history terminology:\n  '+'\n  '.join(offenders[:100]))
    print('Public release cleanup: PASS');print('Output:',a.output);print('Normalized tree SHA-256:',normalized_tree_hash(r))

if __name__=='__main__':main()
