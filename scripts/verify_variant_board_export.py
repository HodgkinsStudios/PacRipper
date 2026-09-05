#!/usr/bin/env python3
"""Independent PacRipper Pac-Man/Puckman source-tree round-trip verifier.
Created by Jacob Hodgkins.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,re,sys
from pathlib import Path
from typing import Dict,List,Tuple
try:
    from archive_support import archive_kind, read_archive_members
except ImportError:
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    from archive_support import archive_kind, read_archive_members

PROFILES={
 'pacman':dict(title='Pac-Man',asm='pacman.asm',program=['pacman.6e','pacman.6f','pacman.6h','pacman.6j'],chars=['pacman.5e'],sprites=['pacman.5f'],proms=['82s123.7f','82s126.4a','82s126.1m','82s126.3m'],chunk=0x1000,expected={
 'pacman.6e':(0x1000,0xC1E6AB10),'pacman.6f':(0x1000,0x1A6FB2D4),'pacman.6h':(0x1000,0xBCDD1BEB),'pacman.6j':(0x1000,0x817D94E3),'pacman.5e':(0x1000,0x0C944964),'pacman.5f':(0x1000,0x958FEDF9),'82s123.7f':(0x20,0x2FC650BD),'82s126.4a':(0x100,0x3EB3A8E4),'82s126.1m':(0x100,0xA9CC86BF),'82s126.3m':(0x100,0x77245B66)},program_sha='e9d4817d70bf1931c25e39a3d626e05dd0d5902d9400097316248a52ff627b77'),
 'puckman':dict(title='Puckman',asm='puckman.asm',program=['pm1_prg1.6e','pm1_prg2.6k','pm1_prg3.6f','pm1_prg4.6m','pm1_prg5.6h','pm1_prg6.6n','pm1_prg7.6j','pm1_prg8.6p'],chars=['pm1_chg1.5e','pm1_chg2.5h'],sprites=['pm1_chg3.5f','pm1_chg4.5j'],proms=['pm1-1.7f','pm1-4.4a','pm1-3.1m','pm1-2.3m'],chunk=0x800,expected={
 'pm1_prg1.6e':(0x800,0xF36E88AB),'pm1_prg2.6k':(0x800,0x618BD9B3),'pm1_prg3.6f':(0x800,0x7D177853),'pm1_prg4.6m':(0x800,0xD3E8914C),'pm1_prg5.6h':(0x800,0x6BF4F625),'pm1_prg6.6n':(0x800,0xA948CE83),'pm1_prg7.6j':(0x800,0xB6289B26),'pm1_prg8.6p':(0x800,0x17A88C13),'pm1_chg1.5e':(0x800,0x2066A0B7),'pm1_chg2.5h':(0x800,0x3591B89D),'pm1_chg3.5f':(0x800,0x9E39323A),'pm1_chg4.5j':(0x800,0x1B1D9096),'pm1-1.7f':(0x20,0x2FC650BD),'pm1-4.4a':(0x100,0x3EB3A8E4),'pm1-3.1m':(0x100,0xA9CC86BF),'pm1-2.3m':(0x100,0x77245B66)},program_sha='de87b3024a309377f5cf438455ed7f37a7aa8b5db5da5189f9b8240f90057cef')
}
INSN=re.compile(r';\s*@INSN\s+\$([0-9A-Fa-f]{4})\s+BYTES=([0-9A-Fa-f ]+)')
DATA=re.compile(r';\s*@DATA\s+\$([0-9A-Fa-f]{4})\s+OWNER=([A-Za-z0-9_]+)')
DB=re.compile(r'^\s*DB\s+(.+?)\s*$',re.I)
HEX=re.compile(r'\$([0-9A-Fa-f]{2})(?=\s*(?:,|$))')
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def crc(b:bytes)->int:
 import zlib;return zlib.crc32(b)&0xffffffff

def profile(root:Path):
 p=root/'manifest/variant.json'
 if p.exists(): key=json.loads(p.read_text())['variant']
 elif (root/'program/puckman.asm').exists(): key='puckman'
 else:key='pacman'
 return key,PROFILES[key]

def load_canonical(path:Path,p:dict)->Dict[str,bytes]:
 names=set(p['expected']); found={}
 if path.is_file() and archive_kind(path) in ('zip','7z'):
  rows={}
  for member,data in read_archive_members(path):
   name=Path(member).name
   if name in names: rows.setdefault(name,[]).append(data)
  for n in names:
   if len(rows.get(n,[]))!=1: raise ValueError(f'canonical input {n}: expected exactly one member')
   found[n]=rows[n][0]
 elif path.is_dir():
  for n in names:
   rows=[x for x in path.rglob(n) if x.is_file()]
   if len(rows)!=1: raise ValueError(f'canonical input {n}: expected exactly one file')
   found[n]=rows[0].read_bytes()
 else: raise ValueError('canonical path must be a folder, ZIP, or 7z')
 for n,(sz,c) in p['expected'].items():
  if len(found[n])!=sz or crc(found[n])!=c: raise ValueError(f'canonical size/CRC mismatch: {n}')
 return found

def rebuild_program(root:Path,p:dict)->bytes:
 blob=bytearray(0x4000); covered=set(); asm=root/'program'/p['asm']
 for raw in asm.read_text().splitlines():
  m=INSN.search(raw)
  if m: addr=int(m.group(1),16); data=bytes(int(x,16) for x in m.group(2).split())
  else:
   d=DATA.search(raw)
   if not d: continue
   addr=int(d.group(1),16); sm=DB.match(raw.split(';',1)[0].strip())
   if not sm: raise ValueError(f'@DATA ${addr:04X} is not DB')
   data=bytes(int(x,16) for x in HEX.findall(sm.group(1)))
  for i,b in enumerate(data):
   a=addr+i
   if a>=0x4000 or a in covered: raise ValueError(f'duplicate/out-of-range program byte ${a:04X}')
   covered.add(a);blob[a]=b
 if len(covered)!=0x4000: raise ValueError(f'program source covers {len(covered)}/16384 bytes')
 if sha(bytes(blob))!=p['program_sha']: raise ValueError(f'program SHA-256 mismatch: {sha(bytes(blob))}')
 return bytes(blob)

def setbit(buf,bo,bm,v):
 mask=1<<(7-bm);buf[bo]=(buf[bo]|mask) if v else (buf[bo]&(~mask&0xff))
def rebuild_graphics(path:Path)->bytes:
 out=bytearray(4096);seen=set()
 with path.open(newline='') as f:
  for r in csv.DictReader(f):
   px=int(r['pixel'])
   for bo,bm,v in ((int(r['msb_rom_byte']),int(r['msb_bit_from_msb']),(px>>1)&1),(int(r['lsb_rom_byte']),int(r['lsb_bit_from_msb']),px&1)):
    if (bo,bm) in seen:raise ValueError('duplicate graphics bit ownership')
    seen.add((bo,bm));setbit(out,bo,bm,v)
 if len(seen)!=32768:raise ValueError(f'graphics bit coverage {len(seen)}/32768')
 return bytes(out)
def rebuild_palette(path):
 out=bytearray(32)
 for r in csv.DictReader(path.open(newline='')):
  v=sum(int(r[f'bit{i}'])<<i for i in range(8));out[int(r['index'])]=v
 return bytes(out)
def rebuild_nibble(path,field):
 out=bytearray(256)
 for r in csv.DictReader(path.open(newline='')):out[int(r['address'])]=int(r[field])|(int(r['serialized_upper_nibble'])<<4)
 return bytes(out)
def rebuild_all(root:Path,p:dict)->Dict[str,bytes]:
 program=rebuild_program(root,p);chars=rebuild_graphics(root/'graphics/character_map.csv');sprites=rebuild_graphics(root/'graphics/sprite_map.csv')
 out={};ch=p['chunk']
 for i,n in enumerate(p['program']):out[n]=program[i*ch:(i+1)*ch]
 for i,n in enumerate(p['chars']):out[n]=chars[i*ch:(i+1)*ch]
 for i,n in enumerate(p['sprites']):out[n]=sprites[i*ch:(i+1)*ch]
 vals=[rebuild_palette(root/'color/palette_source.csv'),rebuild_nibble(root/'color/color_lookup_source.csv','palette_index'),rebuild_nibble(root/'audio/waveform_source.csv','sample_nibble'),rebuild_nibble(root/'audio/timing_prom_source.csv','control_nibble')]
 for n,b in zip(p['proms'],vals):out[n]=b
 return out

def verify(root:Path,canonical_path:Path)->Tuple[bool,List[str]]:
 key,p=profile(root);canonical=load_canonical(canonical_path,p);rebuilt=rebuild_all(root,p);lines=[];ok=True;total=0
 for n in p['expected']:
  a=rebuilt[n];e=canonical[n];match=a==e;ok &= match;total+=len(e);lines.append(f'{n}: {"PASS" if match else "FAIL"} bytes={len(a)}/{len(e)} rebuilt_sha256={sha(a)} canonical_sha256={sha(e)}')
 lines.append(f'variant={key} active_files={len(p["expected"])}/{len(p["expected"])} total_bytes={total}/25376 exact_rebuild={"PASS" if ok else "FAIL"}')
 lines.append(f'program_source=program/{p["asm"]} sha256={p["program_sha"]} PASS')
 return ok,lines

def main():
 ap=argparse.ArgumentParser();ap.add_argument('export_root',type=Path);ap.add_argument('rom_path',type=Path);ap.add_argument('--report',type=Path);a=ap.parse_args()
 try:ok,lines=verify(a.export_root.resolve(),a.rom_path.resolve())
 except Exception as e:print(f'Variant board verification: FAIL: {e}',file=sys.stderr);return 1
 report='PacRipper independent board source reconstruction: '+('PASS' if ok else 'FAIL')+'\n'+'\n'.join(lines)+'\n';print(report,end='')
 if a.report:a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(report)
 return 0 if ok else 1
if __name__=='__main__':raise SystemExit(main())
