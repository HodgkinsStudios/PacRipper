#!/usr/bin/env python3
"""Canonical Pac-Man/Puckman variant profiles for PacRipper.
Created by Jacob Hodgkins.

No ROM payloads are stored here: only names, sizes, CRC32/SHA-256 identities,
physical-to-logical layout rules, and certified normalized program hashes.
"""
from __future__ import annotations
import hashlib, shutil, zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable

@dataclass(frozen=True)
class VariantProfile:
    key: str
    title: str
    asm_name: str
    program_names: tuple[str,...]
    char_names: tuple[str,...]
    sprite_names: tuple[str,...]
    palette_name: str
    lookup_name: str
    waveform_name: str
    timing_name: str
    expected: dict[str, tuple[int,int,str]]
    program_sha256: str

PAC_EXPECTED={
    'pacman.6e':(0x1000,0xC1E6AB10,'fe1c3234df345855d30728637f361f79472cabfe2a892a7567c63eaf31a4217b'),
    'pacman.6f':(0x1000,0x1A6FB2D4,'09a723c9f84790e9019633e37761cfa4e9d7ab6db14f6fdb12738f51fec11065'),
    'pacman.6h':(0x1000,0xBCDD1BEB,'69347409739b64ed9d9b19713de0bc66627bd137687de649796b9d2ef88ed8e6'),
    'pacman.6j':(0x1000,0x817D94E3,'03ee523c210e87fb8dd1d925b092ad269fdd753b5b7a20b3757b0ceee5f18679'),
    'pacman.5e':(0x1000,0x0C944964,'8d9a86c97fe94b1fd010b139672c330e3b257ba59b0d8df7a821592e30a77b4b'),
    'pacman.5f':(0x1000,0x958FEDF9,'49c8f656cb8ea1ae02fb64a2c09df98e7f06a034b43c6c8240032df417c6d36f'),
    '82s123.7f':(0x20,0x2FC650BD,'48fe0b01d68e3d702019ca715f7266c8e3261c769509b281720f53ca0a1cc8fb'),
    '82s126.4a':(0x100,0x3EB3A8E4,'ef8f7a3b0c10f787d9cc1cbc5cc266fcc1afadb24c3b4d610fe252b9c3df1d76'),
    '82s126.1m':(0x100,0xA9CC86BF,'8e723ad91e46ef1a186b2ed3c99a8bf1c571786bc7ceae2b367cbfc80857a394'),
    '82s126.3m':(0x100,0x77245B66,'8c34002652e587aa19a77bff9040d870af18b4b2fe5c5f0ed962899386e0e751'),
}
PUCK_EXPECTED={
    'pm1_prg1.6e':(0x800,0xF36E88AB,'fe96010f87b96e0875838d905d25bb0c836eb49f42d4551b21568a7fe24407d8'),
    'pm1_prg2.6k':(0x800,0x618BD9B3,'3119cc057a351dec04c8c5c3819fb2e4366b1104d55993b2db57dd1035f1448d'),
    'pm1_prg3.6f':(0x800,0x7D177853,'6ff4fe317c2761f1846be5895b25f65377d3a3129df1fcf96d48572e05b89a43'),
    'pm1_prg4.6m':(0x800,0xD3E8914C,'8ea2b7a4942714cff6497aa9121bfb53100c2985305c8b51d1a9a9f96841c22a'),
    'pm1_prg5.6h':(0x800,0x6BF4F625,'f85d305ec213e219e7f65e5b0e6453840b0a013d60c3c292c7921e1bc747d981'),
    'pm1_prg6.6n':(0x800,0xA948CE83,'fdc07080df976eb261e952e397c7009d482ad6bd1c9a44d5b755bf0982b754c6'),
    'pm1_prg7.6j':(0x800,0xB6289B26,'23fc47bdd82fe7fb3a7bf3dbcab1776cc7c29cc9f353c8c2154625f01811edd5'),
    'pm1_prg8.6p':(0x800,0x17A88C13,'cce2579fa744ecda7fb10a07f407b5cadab88571436a44346f088e9637369b79'),
    'pm1_chg1.5e':(0x800,0x2066A0B7,'a6d6965493f1f82275d4fe3b5d4ecdb195328ebf91c68c6c77648d91a0d2bdf8'),
    'pm1_chg2.5h':(0x800,0x3591B89D,'6af15a56317bd09cc20384b6ac1a76ef3ff8f771a8d6f58aa40debc4b959863b'),
    'pm1_chg3.5f':(0x800,0x9E39323A,'5ead861e2d431af3a98fd784451cafe7a137ddbd907cdc442d016e58ded0f60b'),
    'pm1_chg4.5j':(0x800,0x1B1D9096,'f3126288dc09acd8c6f2740f419a51a745165864e6c4c61f6fc836f3deb34800'),
    'pm1-1.7f':(0x20,0x2FC650BD,'48fe0b01d68e3d702019ca715f7266c8e3261c769509b281720f53ca0a1cc8fb'),
    'pm1-4.4a':(0x100,0x3EB3A8E4,'ef8f7a3b0c10f787d9cc1cbc5cc266fcc1afadb24c3b4d610fe252b9c3df1d76'),
    'pm1-3.1m':(0x100,0xA9CC86BF,'8e723ad91e46ef1a186b2ed3c99a8bf1c571786bc7ceae2b367cbfc80857a394'),
    'pm1-2.3m':(0x100,0x77245B66,'8c34002652e587aa19a77bff9040d870af18b4b2fe5c5f0ed962899386e0e751'),
}
PACMAN=VariantProfile('pacman','Pac-Man','pacman.asm',('pacman.6e','pacman.6f','pacman.6h','pacman.6j'),('pacman.5e',),('pacman.5f',),'82s123.7f','82s126.4a','82s126.1m','82s126.3m',PAC_EXPECTED,'e9d4817d70bf1931c25e39a3d626e05dd0d5902d9400097316248a52ff627b77')
PUCKMAN=VariantProfile('puckman','Puckman','puckman.asm',('pm1_prg1.6e','pm1_prg2.6k','pm1_prg3.6f','pm1_prg4.6m','pm1_prg5.6h','pm1_prg6.6n','pm1_prg7.6j','pm1_prg8.6p'),('pm1_chg1.5e','pm1_chg2.5h'),('pm1_chg3.5f','pm1_chg4.5j'),'pm1-1.7f','pm1-4.4a','pm1-3.1m','pm1-2.3m',PUCK_EXPECTED,'de87b3024a309377f5cf438455ed7f37a7aa8b5db5da5189f9b8240f90057cef')
PROFILES=(PACMAN,PUCKMAN)

def crc32(data:bytes)->int: return zlib.crc32(data)&0xffffffff

def _by_basename(root:Path)->dict[str,list[Path]]:
    out={}
    for p in root.rglob('*'):
        if p.is_file(): out.setdefault(p.name.casefold(),[]).append(p)
    return out

def validate_directory(root:Path, profile:VariantProfile)->dict[str,bytes]:
    by=_by_basename(root); out={}
    for name,(size,crc,sha256_expected) in profile.expected.items():
        rows=by.get(name.casefold(),[])
        if len(rows)!=1: raise ValueError(f'{profile.title}: expected exactly one {name}, found {len(rows)}')
        data=rows[0].read_bytes()
        actual_sha256=hashlib.sha256(data).hexdigest()
        if len(data)!=size or crc32(data)!=crc or actual_sha256!=sha256_expected:
            raise ValueError(f'{profile.title}: size/CRC32/SHA-256 mismatch for {name}')
        out[name]=data
    return out

def detect_directory(root:Path)->tuple[VariantProfile,dict[str,bytes]]:
    errors=[]
    for p in PROFILES:
        try: return p,validate_directory(root,p)
        except ValueError as e: errors.append(str(e))
    raise ValueError('unsupported canonical ROM set; only certified pacman.7z/Pac-Man and puckman.zip/Puckman are supported. '+' | '.join(errors))

def normalized_program(profile:VariantProfile, files:dict[str,bytes])->bytes:
    return b''.join(files[n] for n in profile.program_names)

def normalized_chars(profile:VariantProfile, files:dict[str,bytes])->bytes:
    return b''.join(files[n] for n in profile.char_names)

def normalized_sprites(profile:VariantProfile, files:dict[str,bytes])->bytes:
    return b''.join(files[n] for n in profile.sprite_names)

def logical_proms(profile:VariantProfile, files:dict[str,bytes])->dict[str,bytes]:
    return {'82s123.7f':files[profile.palette_name],'82s126.4a':files[profile.lookup_name],'82s126.1m':files[profile.waveform_name],'82s126.3m':files[profile.timing_name]}

def prepare_core_directory(source:Path,dest:Path,profile:VariantProfile,files:dict[str,bytes])->Path:
    """Make a private core-input tree. Puckman keeps its 16 physical members and gains
    normalized logical aliases used only by the shared board-resource codecs."""
    if dest.exists(): shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for name,data in files.items(): (dest/name).write_bytes(data)
    if profile.key=='puckman':
        program=normalized_program(profile,files)
        for i,name in enumerate(('pacman.6e','pacman.6f','pacman.6h','pacman.6j')):
            (dest/name).write_bytes(program[i*0x1000:(i+1)*0x1000])
        chars=normalized_chars(profile,files); sprites=normalized_sprites(profile,files)
        (dest/'pacman.5e').write_bytes(chars); (dest/'pacman.5f').write_bytes(sprites)
        for name,data in logical_proms(profile,files).items(): (dest/name).write_bytes(data)
    return dest

def physical_chunks(profile:VariantProfile, program:bytes, chars:bytes, sprites:bytes, proms:dict[str,bytes])->dict[str,bytes]:
    out={}
    pchunk=0x1000 if profile.key=='pacman' else 0x800
    for i,n in enumerate(profile.program_names): out[n]=program[i*pchunk:(i+1)*pchunk]
    cchunk=0x1000 if profile.key=='pacman' else 0x800
    for i,n in enumerate(profile.char_names): out[n]=chars[i*cchunk:(i+1)*cchunk]
    schunk=0x1000 if profile.key=='pacman' else 0x800
    for i,n in enumerate(profile.sprite_names): out[n]=sprites[i*schunk:(i+1)*schunk]
    out[profile.palette_name]=proms['82s123.7f']; out[profile.lookup_name]=proms['82s126.4a']; out[profile.waveform_name]=proms['82s126.1m']; out[profile.timing_name]=proms['82s126.3m']
    return out
