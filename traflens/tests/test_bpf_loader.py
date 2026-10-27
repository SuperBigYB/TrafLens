#!/usr/bin/env python3
"""Independent small ELF vectors; no compiler, BPF syscall or native loader."""
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve()
# Both the private review pair and normal traflens/{scripts,tests} layout work.
TOOL = next(path for path in (HERE.with_name('check-bpf-loader.py'),
                             HERE.parents[1] / 'scripts' / 'check-bpf-loader.py')
            if path.is_file())
spec = importlib.util.spec_from_file_location('bpf_loader_contract', TOOL)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

EXIT = bytes.fromhex('95 00 00 00 00 00 00 00')
HELPER = bytes.fromhex('85 00 00 00 04 00 00 00') + EXIT
PSEUDO = bytes.fromhex('85 10 00 00 ff ff ff ff') + EXIT
MAP = bytes.fromhex('18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00') + EXIT


def elf(code=HELPER, relocation=None, debug=False, extra_text=None, symbol_section=2,
        symbol_type=1, symbol_value=0, symbol_size=32):
    # A hand-encoded ET_REL with one code section and a legacy maps definition.
    entries = [dict(name='', kind=0, flags=0, data=b''),
               dict(name='kprobe/unit', kind=1, flags=6, data=code),
               dict(name='maps', kind=1, flags=3, data=b'\0' * 32),
               dict(name='.symtab', kind=2, flags=0,
                    data=b'\0' * 24 + struct.pack('<IBBHQQ', 1, 16 | symbol_type, 0,
                                                symbol_section, symbol_value, symbol_size),
                    link=4, entsize=24),
               dict(name='.strtab', kind=3, flags=0, data=b'\0map0\0'),
               dict(name='.shstrtab', kind=3, flags=0, data=b'')]
    if relocation is not None:
        offset, kind, sym, rela = relocation
        entries.append(dict(name='.rel.kprobe/unit', kind=4 if rela else 9, flags=0,
                            data=struct.pack('<QQ', offset, (sym << 32) | kind) + (b'\0' * 8 if rela else b''),
                            link=3, info=1, entsize=24 if rela else 16))
    if debug:
        target=len(entries)
        entries.append(dict(name='.BTF.ext', kind=1, flags=0, data=b'\0' * 8))
        entries.append(dict(name='.rel.BTF.ext', kind=9, flags=0,
                            data=struct.pack('<QQ', 0, (0xffffffff << 32) | 10),
                            link=3, info=target, entsize=16))
    if extra_text is not None:
        entries.append(dict(name='.text', kind=1, flags=6, data=extra_text))
    names=b''; offsets=[]
    for entry in entries:
        offsets.append(len(names));names+=entry['name'].encode()+b'\0'
    entries[5]['data']=names
    data=bytearray(b'\0'*64); headers=[]
    for i,entry in enumerate(entries):
        offset=len(data);data+=entry['data']
        headers.append((offsets[i],entry['kind'],entry['flags'],0,offset,len(entry['data']),
                        entry.get('link',0),entry.get('info',0),1,entry.get('entsize',0)))
    table=len(data)
    for header in headers:data+=struct.pack('<IIQQQQIIQQ',*header)
    ident=b'\x7fELF'+bytes((2,1,1))+b'\0'*9
    data[:64]=struct.pack('<16sHHIQQQIHHHHHH',ident,1,247,1,0,0,table,0,64,0,0,64,len(entries),5)
    return bytes(data),table


class LoaderContract(unittest.TestCase):
    def test_helper_calls_src_zero_are_allowed(self):
        report=m.check_bytes(elf()[0])
        self.assertEqual(report['helper_calls'],1)
        # elf.c does not register an unreferenced .text without a REL target.
        self.assertEqual(m.check_bytes(elf(extra_text=EXIT)[0])['helper_calls'],1)

    def test_valid_map_ldimm64_and_debug_function_relocation(self):
        report=m.check_bytes(elf(MAP,(0,1,1,False),debug=True)[0])
        self.assertEqual(report['map_relocations'],1)

    def test_pseudo_call_rejected_even_without_relocation(self):
        with self.assertRaisesRegex(m.ContractError,'BPF_PSEUDO_CALL'):
            m.check_bytes(elf(PSEUDO)[0])

    def test_all_exec_sections_include_outlined_text(self):
        with self.assertRaisesRegex(m.ContractError,r'\.text.*BPF_PSEUDO_CALL'):
            m.check_bytes(elf(extra_text=PSEUDO)[0])

    def test_function_relocation_rejected_independently_of_call_source(self):
        with self.assertRaisesRegex(m.ContractError,'relocation type=10'):
            m.check_bytes(elf(HELPER,(0,10,1,False))[0])

    def test_executable_relocation_requires_ldimm64_and_map_symbol(self):
        vectors=[elf(HELPER,(0,1,1,False))[0],
                 elf(MAP,(0,1,1,False),symbol_section=1,symbol_type=2)[0],
                 elf(MAP,(0,1,1,False),symbol_section=4)[0]]
        for blob in vectors:
            with self.subTest(blob=blob[-16:]),self.assertRaises(m.ContractError):m.check_bytes(blob)

    def test_executable_rela_is_unsupported(self):
        with self.assertRaisesRegex(m.ContractError,'RELA unsupported'):
            m.check_bytes(elf(MAP,(0,1,1,True))[0])

    def test_relocation_offsets_and_symbol_bounds_fail_closed(self):
        vectors=[elf(MAP,(1,1,1,False))[0],elf(MAP,(8,1,1,False))[0],
                 elf(MAP,((1<<64)-8,1,1,False))[0],elf(MAP,(0,1,2,False))[0],
                 elf(MAP,(0,1,1,False),symbol_value=32)[0],
                 elf(MAP,(0,1,1,False),symbol_size=0)[0]]
        for blob in vectors:
            with self.subTest(vector=vectors.index(blob)),self.assertRaises(m.ContractError):m.check_bytes(blob)

    def test_interior_map_symbol_obeys_real_loader_span(self):
        # Symbol extent fits (1+16 <=32), but the one-map loader span is32.
        with self.assertRaisesRegex(m.ContractError,'loader map span'):
            m.check_bytes(elf(MAP,(0,1,1,False),symbol_value=1,symbol_size=16)[0])

    def test_malformed_instruction_boundaries(self):
        for code in (b'\x95'*7,MAP[:8],MAP[:8]+b'\x01'+b'\0'*7):
            with self.subTest(code=code.hex()),self.assertRaises(m.ContractError):m.check_bytes(elf(code)[0])

    def test_every_truncated_prefix_raises_typed_error(self):
        blob,_=elf(MAP,(0,1,1,False),debug=True)
        for length in range(len(blob)):
            with self.subTest(length=length),self.assertRaises(m.ContractError):m.check_bytes(blob[:length])

    def test_bad_headers_and_table_bounds(self):
        blob,table=elf(MAP,(0,1,1,False))
        changes=[(4,b'\x01'),(5,b'\x02'),(18,struct.pack('<H',62)),
                 (40,struct.pack('<Q',(1<<64)-1)),(58,struct.pack('<H',0)),
                 (table+6*64+44,struct.pack('<I',999))]
        for offset,value in changes:
            bad=bytearray(blob);bad[offset:offset+len(value)]=value
            with self.subTest(offset=offset),self.assertRaises(m.ContractError):m.check_bytes(bytes(bad))

    def test_cli_count_and_no_matches_are_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'good.elf';path.write_bytes(elf()[0])
            good=subprocess.run([sys.executable,str(TOOL),str(path),'--expect-count','1'],capture_output=True,text=True)
            self.assertEqual(good.returncode,0,good.stderr)
            self.assertTrue(json.loads(good.stdout)['passed'])
            bad=subprocess.run([sys.executable,str(TOOL),str(path),'--expect-count','10'],capture_output=True,text=True)
            self.assertEqual(bad.returncode,1)
            empty=subprocess.run([sys.executable,str(TOOL),str(Path(directory)/'absent*.elf')],capture_output=True,text=True)
            self.assertEqual(empty.returncode,1)


if __name__=='__main__':unittest.main(verbosity=2)
