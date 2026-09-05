#!/usr/bin/env python3
"""Write a PacRipper release's exact physical Pac-Man or Puckman ROM set.
Created by Jacob Hodgkins.
The Z80 source must be assembled independently first; this helper consumes that 16-KiB binary.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path

def load_verifier(root:Path):
 p=root/'verification/verify_complete_board_export.py'
 if not p.exists():p=Path(__file__).resolve().with_name('verify_variant_board_export.py')
 spec=importlib.util.spec_from_file_location('pacripper_variant_verifier',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def main():
 ap=argparse.ArgumentParser();ap.add_argument('release',type=Path);ap.add_argument('program_bin',type=Path);ap.add_argument('output',type=Path);ap.add_argument('--canonical',type=Path);a=ap.parse_args()
 root=a.release.resolve();v=load_verifier(root);key,p=v.profile(root);program=a.program_bin.resolve().read_bytes()
 if len(program)!=0x4000:raise SystemExit(f'FAIL: assembled program is {len(program)} bytes; expected 16384')
 digest=hashlib.sha256(program).hexdigest()
 if digest!=p['program_sha']:raise SystemExit(f'FAIL: assembled {p["title"]} program SHA-256 mismatch: {digest}')
 # Reuse structured resource reconstructors, but inject the externally assembled program.
 chars=v.rebuild_graphics(root/'graphics/character_map.csv');sprites=v.rebuild_graphics(root/'graphics/sprite_map.csv');ch=p['chunk'];out={}
 for i,n in enumerate(p['program']):out[n]=program[i*ch:(i+1)*ch]
 for i,n in enumerate(p['chars']):out[n]=chars[i*ch:(i+1)*ch]
 for i,n in enumerate(p['sprites']):out[n]=sprites[i*ch:(i+1)*ch]
 vals=[v.rebuild_palette(root/'color/palette_source.csv'),v.rebuild_nibble(root/'color/color_lookup_source.csv','palette_index'),v.rebuild_nibble(root/'audio/waveform_source.csv','sample_nibble'),v.rebuild_nibble(root/'audio/timing_prom_source.csv','control_nibble')]
 for n,b in zip(p['proms'],vals):out[n]=b
 dst=a.output.resolve();dst.mkdir(parents=True,exist_ok=True)
 for n,b in out.items():(dst/n).write_bytes(b);print(f'{n}: {len(b)} bytes sha256={hashlib.sha256(b).hexdigest()}')
 print(f'variant={key} active_files={len(out)}/{len(out)} total_bytes={sum(map(len,out.values()))}/25376')
 if a.canonical:
  c=v.load_canonical(a.canonical.resolve(),p);bad=[n for n in out if out[n]!=c[n]]
  if bad:raise SystemExit('canonical_round_trip=FAIL mismatches='+','.join(bad))
  print(f'canonical_round_trip=PASS {len(out)}/{len(out)} files 25376/25376 bytes exact')
 return 0
if __name__=='__main__':raise SystemExit(main())
