#!/usr/bin/env python3
"""Generate PacRipper's complete Puckman 16-file source release from canonical Puckman input.
Created by Jacob Hodgkins.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,shutil,subprocess,sys
from pathlib import Path
SCRIPT=Path(__file__).resolve();ROOT=SCRIPT.parent.parent;sys.path.insert(0,str(SCRIPT.parent))
import complete_board_recovery as base
import verify_variant_board_export as vverify
from variant_support import PUCKMAN,validate_directory

def run(cmd,cwd=ROOT):
 p=subprocess.run([str(x) for x in cmd],cwd=cwd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 if p.returncode:print(p.stdout,file=sys.stderr);raise RuntimeError('command failed: '+' '.join(map(str,cmd)))
 return p.stdout

def copy(src,dst):dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
def read_csv(p):
 with p.open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def write_csv(p,fields,rows):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('w',newline='',encoding='utf-8') as f:w=csv.DictWriter(f,fieldnames=fields,lineterminator='\n');w.writeheader();w.writerows(rows)

def map_program(filename,offset):
 pac=['pacman.6e','pacman.6f','pacman.6h','pacman.6j'];bank=pac.index(filename);addr=bank*0x1000+int(offset);idx=addr//0x800;return PUCKMAN.program_names[idx],addr%0x800
def map_nonprogram(filename,offset):
 off=int(offset)
 if filename=='pacman.5e':return PUCKMAN.char_names[off//0x800],off%0x800
 if filename=='pacman.5f':return PUCKMAN.sprite_names[off//0x800],off%0x800
 m={'82s123.7f':PUCKMAN.palette_name,'82s126.4a':PUCKMAN.lookup_name,'82s126.1m':PUCKMAN.waveform_name,'82s126.3m':PUCKMAN.timing_name}
 return m[filename],off

def transform_ownership(out):
 p=out/'manifest/board_byte_ownership.csv';rows=read_csv(p);fields=list(rows[0])
 for r in rows:
  if r['file'].startswith('pacman.6'):r['file'],r['byte_offset']=map_program(r['file'],r['byte_offset'])
  else:r['file'],r['byte_offset']=map_nonprogram(r['file'],r['byte_offset'])
  r['source_export_location']=r['source_export_location'].replace('program/pacman.asm','program/puckman.asm')
 write_csv(p,fields,rows)
 p=out/'manifest/board_nonprogram_bit_ownership.csv';rows=read_csv(p);fields=list(rows[0])
 for r in rows:r['file'],r['byte_offset']=map_nonprogram(r['file'],r['byte_offset'])
 write_csv(p,fields,rows)

def write_manifest(out,files):
 fields=['filename','manifest_status','resource_class','size','crc32','sha256','source_provenance','decoder_owner','decoded_records','roundtrip_status','relationship']
 classes={**{n:'program' for n in PUCKMAN.program_names},**{n:'character_graphics' for n in PUCKMAN.char_names},**{n:'sprite_graphics' for n in PUCKMAN.sprite_names},PUCKMAN.palette_name:'palette_prom',PUCKMAN.lookup_name:'color_lookup_prom',PUCKMAN.waveform_name:'waveform_prom',PUCKMAN.timing_name:'sound_timing_control_prom'}
 rows=[]
 import zlib
 for n in PUCKMAN.expected:
  data=files[n];rows.append(dict(filename=n,manifest_status='active_canonical',resource_class=classes[n],size=len(data),crc32=f'{zlib.crc32(data)&0xffffffff:08X}',sha256=hashlib.sha256(data).hexdigest(),source_provenance='external_user_input:'+n,decoder_owner='PacRipper shared Pac-Man-family codec',decoded_records='source_owned',roundtrip_status='PASS',relationship='canonical_puckman_16_file_manifest'))
 write_csv(out/'manifest/board_manifest.csv',fields,rows)
 write_csv(out/'manifest/excluded_archive_members.csv',fields,[])

def copy_sources(program_export,resources,out):
 metrics=base.build_release_program_sources(program_export,out)
 asm=out/'program/pacman.asm';puck=out/'program/puckman.asm';asm.rename(puck)
 text=puck.read_text();text=text.replace('; Pac-Man (Midway/Namco hardware) release-quality Z80 disassembly','; Puckman (Namco Pac-Man-family hardware) release-quality Z80 disassembly',1);puck.write_text(text)
 m=out/'program/release_metrics.txt';m.write_text(m.read_text().replace('Pac-Man release disassembly','Puckman release disassembly').replace('program/pacman.asm','program/puckman.asm'))
 selections={'graphics':['characters.csv','sprites.csv','character_map.csv','sprite_map.csv','character_sheet.ppm','sprite_sheet.ppm','bit_ownership.csv'],'color':['palette_source.csv','color_lookup_source.csv','palette_map.csv','color_lookup_map.csv','palette_sheet.ppm','color_lookup_sheet.ppm','bit_ownership.csv','COLOR_SEMANTICS.txt'],'audio':['waveform_source.csv','timing_prom_source.csv','waveform_map.csv','timing_prom_map.csv','waveform_table.txt','bit_ownership.csv','AUDIO_PROM_SEMANTICS.txt']}
 for folder,names in selections.items():
  for n in names:
   src=resources/folder/n
   if src.exists():copy(src,out/folder/n)
 copy(ROOT/'scripts/verify_variant_board_export.py',out/'verification/verify_complete_board_export.py')
 copy(ROOT/'scripts/build_variant_rom_set.py',out/'verification/build_complete_rom_set.py')
 copy(ROOT/'scripts/archive_support.py',out/'verification/archive_support.py')
 return metrics

def docs(out):
 (out/'manifest/variant.json').write_text(json.dumps({'variant':'puckman','title':'Puckman','assembly_source':'program/puckman.asm','physical_files':16,'board_bytes':25376,'program_sha256':PUCKMAN.program_sha256},indent=2)+'\n')
 (out/'PUCKMAN_VARIANT_SEMANTICS.md').write_text('''# Puckman Variant Semantics\n\n**Created by Jacob Hodgkins**\n\nPacRipper treats canonical Puckman as a separately reconstructed Pac-Man-family variant. The normalized 16-KiB program has the same 5,414 instruction starts as canonical Pac-Man. The executable variant difference is the checksum-limit operand at `$3020`: Puckman decodes `CP $40` where Pac-Man decodes `CP $30`. The remaining normalized program differences are variant data: 20 DrawText pointer redirects and the Pac-Man replacement-text block `$3D00-$3E5B`, which is zero-filled in Puckman. Character graphics differ by two bytes; sprite graphics and all four PROM contents are identical after logical normalization.\n\nThis release is generated from the supplied Puckman bytes and is independently round-tripable to Puckman's native 16-file physical layout.\n''')
 (out/'README.md').write_text(f'''# Puckman Complete Board Disassembly\n\n**Created by Jacob Hodgkins**\n\nThis package is a self-contained source representation generated from the canonical 16-file Puckman ROM set. `program/puckman.asm` contains the complete 16-KiB Puckman Z80 program source; graphics, color, waveform and timing/control resources are represented by editable structured sources.\n\n- Z80 instructions: 5,414 / 5,414\n- Program bytes: 16,384 / 16,384\n- Physical board files: 16 / 16\n- Board bytes: 25,376 / 25,376\n- Expected assembled program SHA-256: `{PUCKMAN.program_sha256}`\n\nThe output is independent of the Pac-Man disassembly. Assemble `program/puckman.asm` with SjASMPlus, then run `python3 verification/build_complete_rom_set.py . build/puckman_program.bin build/romset --canonical /path/to/puckman.zip` to reproduce all 16 physical files byte-for-byte.\n''')
 (out/'BUILDING_COMPLETE_ROM_SET.md').write_text('''# Building the Complete Puckman ROM Set\n\n**Created by Jacob Hodgkins**\n\nFrom this release root:\n\n```text\nmkdir -p build\nsjasmplus --raw=build/puckman_program.bin program/puckman.asm\npython3 verification/build_complete_rom_set.py . build/puckman_program.bin build/puckman_romset --canonical /path/to/puckman.zip\n```\n\nThe assembler output must be exactly 16,384 bytes with SHA-256 `de87b3024a309377f5cf438455ed7f37a7aa8b5db5da5189f9b8240f90057cef`. The rebuild helper then writes Puckman's native 16-file layout.\n''')
 (out/'ROUND_TRIP_REBUILD_CERTIFICATION.md').write_text('''# Puckman Round-Trip Rebuild Certification\n\n**Created by Jacob Hodgkins**\n\nCertification requires external SjASMPlus assembly of `program/puckman.asm`, exact 16-KiB program SHA-256, and byte-for-byte reconstruction of all 16 physical ROM/PROM files (25,376/25,376 bytes).\n''')

def main():
 ap=argparse.ArgumentParser();ap.add_argument('core_rom_dir',type=Path);ap.add_argument('canonical_rom_dir',type=Path);ap.add_argument('out_dir',type=Path);a=ap.parse_args()
 files=validate_directory(a.canonical_rom_dir.resolve(),PUCKMAN);out=a.out_dir.resolve();work=out.parent/(out.name+'.work');shutil.rmtree(out,ignore_errors=True);shutil.rmtree(work,ignore_errors=True);work.mkdir(parents=True)
 binary=ROOT/'bin'/('PacRipperCore.exe' if __import__('os').name=='nt' else 'PacRipperCore');pe=work/'program_export';res=work/'resources'
 stdout=run([binary,'--program-export',a.core_rom_dir.resolve(),pe]);run([binary,'--board-export',a.core_rom_dir.resolve(),res]);out.mkdir(parents=True)
 metrics=copy_sources(pe,res,out);base.build_byte_ledger(pe,res,out);base.build_bit_ledger(res,out);transform_ownership(out);write_manifest(out,files);docs(out)
 ok,lines=vverify.verify(out,a.canonical_rom_dir.resolve())
 if not ok:raise RuntimeError('independent Puckman source reconstruction failed')
 (out/'verification/source_rebuild_report.txt').write_text('Complete Puckman board source reconstruction: PASS\n'+'\n'.join(lines)+'\n')
 (out/'verification/complete_board_certification.txt').write_text(f'Complete Puckman Board Recovery: PASS\nphysical files=16/16\nboard bytes=25376/25376\nprogram source=program/puckman.asm\nprogram sha256={PUCKMAN.program_sha256}\nindependent source reconstruction=PASS 16/16 files byte-exact\n')
 base.build_hash_manifest(out);(out/'verification/source_tree_sha256.txt').write_text(base.normalized_tree_digest(out)+'\n');shutil.rmtree(work)
 print('Complete Puckman Board ROM/PROM Recovery: PASS');print('5414/5414 instructions; 16384/16384 program bytes');print('program_sha256='+PUCKMAN.program_sha256);print('physical_files=16/16 board_bytes=25376/25376')
 return 0
if __name__=='__main__':raise SystemExit(main())
