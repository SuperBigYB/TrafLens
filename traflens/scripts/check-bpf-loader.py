#!/usr/bin/env python3
"""Check native BPF ELF artifacts against TrafLens's map-only userspace loader.

Selected offline ELF64 little-endian/EM_BPF structural checks, not a complete
ELF loader, relocation simulator or kernel verifier. user/load.c rewrites
LDIMM64 map relocations; it does not link BPF subprograms. An unreferenced,
nonempty .text is not rejected solely by its name or size.
"""
import argparse
import glob
import hashlib
import json
from pathlib import Path
import struct

EHDR = struct.Struct('<16sHHIQQQIHHHHHH')
SHDR = struct.Struct('<IIQQQQIIQQ')
SYM = struct.Struct('<IBBHQQ')
REL = struct.Struct('<QQ')
RELA = struct.Struct('<QQq')
MAX_FILE_BYTES = 128 * 1024 * 1024
SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_NOBITS, SHT_REL = 1, 2, 3, 4, 8, 9
SHF_EXECINSTR = 4


class ContractError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise ContractError(message)


def bounded(data, offset, size, context):
    require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset,
            context + ': file bounds exceeded')
    return data[offset:offset + size]


def string(table, offset, context):
    require(0 <= offset < len(table), context + ': string offset out of bounds')
    end = table.find(b'\0', offset)
    require(end >= 0, context + ': unterminated string')
    return table[offset:end].decode('utf-8', errors='replace')


def check_bytes(data):
    require(len(data) <= MAX_FILE_BYTES, 'artifact exceeds bounded file size')
    bounded(data, 0, EHDR.size, 'ELF header')
    (ident, kind, machine, version, entry, phoff, shoff, flags, ehsize,
     phentsize, phnum, shentsize, shnum, shstrndx) = EHDR.unpack_from(data)
    require(ident[:4] == b'\x7fELF' and ident[4:7] == bytes((2, 1, 1)),
            'requires ELF64 little-endian version1')
    require(kind == 1 and machine == 247 and version == 1,
            'requires ET_REL / EM_BPF / version1')
    require(ehsize == EHDR.size and shentsize == SHDR.size, 'invalid ELF header/table stride')
    require(0 < shnum < 0xff00 and 0 < shstrndx < shnum,
            'missing/unsupported extended section numbering')
    require(shoff >= EHDR.size, 'section table overlaps ELF header')
    bounded(data, shoff, shnum * shentsize, 'section table')
    if phnum:
        require(phentsize == 56, 'invalid program-header stride')
        bounded(data, phoff, phnum * phentsize, 'program table')
    sections = []
    for index in range(shnum):
        values = SHDR.unpack_from(data, shoff + index * shentsize)
        section = dict(zip(('name_offset', 'type', 'flags', 'address', 'offset', 'size',
                            'link', 'info', 'alignment', 'entsize'), values))
        if section['type'] == SHT_NOBITS:
            bounded(data, section['offset'], 0, 'NOBITS section')
        else:
            bounded(data, section['offset'], section['size'], 'section ' + str(index))
        sections.append(section)
    require(sections[0]['type'] == 0, 'section zero must be SHT_NULL')
    names_section = sections[shstrndx]
    require(names_section['type'] == SHT_STRTAB, 'section-name table is not STRTAB')
    names = bounded(data, names_section['offset'], names_section['size'], 'section names')
    map_spans = {}
    for section in sections:
        section['name'] = string(names, section['name_offset'], 'section name')

    executable, helper_calls, map_relocations = [], 0, 0
    for index, section in enumerate(sections):
        if not section['flags'] & SHF_EXECINSTR:
            continue
        require(section['type'] == SHT_PROGBITS, section['name'] + ': executable section is not PROGBITS')
        require(section['size'] % 8 == 0, section['name'] + ': incomplete BPF instruction')
        code = bounded(data, section['offset'], section['size'], section['name'])
        offset = 0
        while offset < len(code):
            opcode, registers = code[offset], code[offset + 1]
            if opcode == 0x18:  # LD | IMM | DW occupies two instruction slots.
                require(offset + 16 <= len(code), section['name'] + ': truncated LDIMM64')
                require(code[offset + 8:offset + 12] == b'\0' * 4,
                        section['name'] + ': malformed LDIMM64 continuation')
                offset += 16
                continue
            if opcode == 0x85:
                src = registers >> 4
                require(src == 0, section['name'] + ':' + str(offset) +
                        ': unsupported BPF call src=' + str(src) +
                        (' (BPF_PSEUDO_CALL)' if src == 1 else ''))
                helper_calls += 1
            offset += 8
        executable.append({'index': index, 'name': section['name'], 'bytes': section['size']})
    require(any(s['bytes'] for s in executable), 'no nonempty executable BPF sections')

    for section in sections:
        if section['type'] not in (SHT_REL, SHT_RELA):
            continue
        stride = REL.size if section['type'] == SHT_REL else RELA.size
        require(section['entsize'] == stride and section['size'] % stride == 0,
                section['name'] + ': malformed relocation table')
        require(section['info'] < shnum, section['name'] + ': relocation target out of bounds')
        target = sections[section['info']]
        # Debug/BTF metadata relocations do not target an executable section.
        if not target['flags'] & SHF_EXECINSTR:
            continue
        require(section['type'] == SHT_REL, section['name'] + ': executable RELA unsupported by map-only loader')
        require(0 < section['link'] < shnum, section['name'] + ': symbol table index out of bounds')
        syms = sections[section['link']]
        require(syms['type'] == SHT_SYMTAB and syms['entsize'] == SYM.size and syms['size'] % SYM.size == 0,
                section['name'] + ': invalid SYMTAB')
        require(0 < syms['link'] < shnum and sections[syms['link']]['type'] == SHT_STRTAB,
                section['name'] + ': invalid symbol string table')
        strings_section = sections[syms['link']]
        strings = bounded(data, strings_section['offset'], strings_section['size'], 'symbol strings')
        seen = set()
        for offset in range(0, section['size'], stride):
            relo, info = REL.unpack_from(data, section['offset'] + offset)
            require(info & 0xffffffff == 1, section['name'] + ': executable relocation type=' + str(info & 0xffffffff) + ' is not R_BPF_64_64 map relocation')
            require(relo % 8 == 0 and relo <= target['size'] and 16 <= target['size'] - relo,
                    section['name'] + ': relocation instruction bounds/alignment')
            require(relo not in seen, section['name'] + ': duplicate relocation offset')
            seen.add(relo)
            at = target['offset'] + relo
            require(data[at] == 0x18 and data[at + 8:at + 12] == b'\0' * 4,
                    section['name'] + ': relocation does not target complete LDIMM64')
            symbol_index = info >> 32
            require(symbol_index < syms['size'] // SYM.size, section['name'] + ': symbol index out of bounds')
            name_offset, symbol_info, other, symbol_section, value, size = SYM.unpack_from(data, syms['offset'] + symbol_index * SYM.size)
            name = string(strings, name_offset, 'symbol name')
            require(symbol_info & 15 != 2, section['name'] + ': function relocation unsupported')
            require(0 < symbol_section < shnum and sections[symbol_section]['name'] == 'maps',
                    section['name'] + ': relocation symbol is not a legacy maps definition')
            maps = sections[symbol_section]
            require(maps['type'] == SHT_PROGBITS and name and 0 < size and value < maps['size'] and size <= maps['size'] - value,
                    section['name'] + ': map symbol outside maps section')
            key = (section['link'], symbol_section)
            if key not in map_spans:
                # Match load.c's first pass exactly: count all symbols whose
                # st_shndx is maps, including unnamed/section-type symbols.
                count = sum(SYM.unpack_from(data, syms['offset'] + index * SYM.size)[3] == symbol_section
                            for index in range(syms['size'] // SYM.size))
                require(count > 0, section['name'] + ': no map symbols')
                map_spans[key] = maps['size'] // count
            span = map_spans[key]
            require(span > 0 and span <= maps['size'] - value,
                    section['name'] + ': loader map span exceeds maps section')
            map_relocations += 1
    return {'sha256': hashlib.sha256(data).hexdigest(), 'executable_sections': executable,
            'helper_calls': helper_calls, 'map_relocations': map_relocations}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('artifacts', nargs='+', help='ELF paths or quoted recursive glob patterns')
    parser.add_argument('--expect-count', type=int)
    args = parser.parse_args()
    paths = set()
    errors, reports = [], []
    for pattern in args.artifacts:
        matches = glob.glob(pattern, recursive=True) if glob.has_magic(pattern) else [pattern]
        if not matches:
            errors.append({'path': pattern, 'error': 'pattern matched no artifacts'})
        paths.update(Path(path).resolve() for path in matches)
    if args.expect_count is not None and (args.expect_count <= 0 or len(paths) != args.expect_count):
        errors.append({'error': 'expected artifact count differs', 'expected': args.expect_count, 'actual': len(paths)})
    for path in sorted(paths):
        try:
            require(path.stat().st_size <= MAX_FILE_BYTES, 'artifact exceeds bounded file size')
            reports.append({'path': str(path), **check_bytes(path.read_bytes())})
        except (OSError, ContractError) as error:
            errors.append({'path': str(path), 'error': str(error)})
    print(json.dumps({'schema': 'traflens.bpf-loader-contract.v1', 'passed': not errors,
                      'checked_files': len(paths), 'passed_files': len(reports), 'files': reports, 'errors': errors}, indent=2))
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
