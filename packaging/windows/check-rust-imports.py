#!/usr/bin/env python3
"""Build-time gate for direct imports of our x64 Rust EXEs, not a DLL resolver."""
import argparse
import json
from pathlib import Path
import re
import struct


class InvalidPE(ValueError):
    pass


def imports(data):
    if not 64 <= len(data) <= 128 * 1024 * 1024:
        raise InvalidPE('PE size outside supported bounds')

    def need(offset, size):
        if offset < 0 or size < 0 or offset + size > len(data):
            raise InvalidPE('truncated PE range')

    def unpack(fmt, offset):
        need(offset, struct.calcsize(fmt))
        return struct.unpack_from(fmt, data, offset)

    if data[:2] != b'MZ':
        raise InvalidPE('missing DOS signature')
    pe, = unpack('<I', 60)
    need(pe, 24)
    if pe < 64 or data[pe:pe + 4] != b'PE\0\0':
        raise InvalidPE('missing PE signature')
    machine, count = unpack('<HH', pe + 4)
    optional_size, characteristics = unpack('<HH', pe + 20)
    if machine != 0x8664 or not 1 <= count <= 96 or not characteristics & 2 or characteristics & 0x2000:
        raise InvalidPE('expected an x64 executable, not a DLL')
    optional = pe + 24
    need(optional, optional_size)
    if optional_size < 128 or unpack('<H', optional)[0] != 0x20b:
        raise InvalidPE('expected PE32+ optional header')
    directories, = unpack('<I', optional + 108)
    if not 2 <= directories <= 16 or 112 + directories * 8 > optional_size:
        raise InvalidPE('invalid data directories')
    # Fail closed rather than silently miss a runtime in a delay-import table.
    if directories > 13 and unpack('<II', optional + 112 + 13 * 8) != (0, 0):
        raise InvalidPE('delay imports unsupported by this Rust EXE gate')
    table = optional + optional_size
    need(table, count * 40)
    headers, = unpack('<I', optional + 60)
    if not table + count * 40 <= headers <= len(data):
        raise InvalidPE('invalid header extent')
    sections = []
    for i in range(count):
        virtual_size, address, size, raw = unpack('<IIII', table + i * 40 + 8)
        extent = max(virtual_size, size)
        if not extent or address < headers or address + extent > 0x100000000:
            raise InvalidPE('invalid section virtual extent')
        need(raw, size)
        if size and raw < headers:
            raise InvalidPE('section overlaps headers')
        for va, vs, rp, rs in sections:
            if address < va + vs and va < address + extent:
                raise InvalidPE('overlapping virtual sections')
            if size and rs and raw < rp + rs and rp < raw + size:
                raise InvalidPE('overlapping raw sections')
        sections.append((address, extent, raw, size))

    def mapped(rva, size):
        if rva < headers and rva + size <= headers:
            return rva, headers
        for va, _, raw, raw_size in sections:
            if va <= rva and rva + size <= va + raw_size:
                return raw + rva - va, raw + raw_size
        raise InvalidPE('RVA is not backed by bounded file data')

    rva, size = unpack('<II', optional + 120)
    if (rva, size) == (0, 0):
        return []
    if not rva or not 20 <= size <= len(data):
        raise InvalidPE('invalid import directory extent')
    offset, _ = mapped(rva, size)
    names = []
    # The directory can include thunks/names after the descriptor array.
    for descriptor in range(offset, offset + min(size, 20 * 257) - 19, 20):
        fields = unpack('<IIIII', descriptor)
        if fields == (0, 0, 0, 0, 0):
            return names
        name, end = mapped(fields[3], 1)
        limit = min(end, name + 261)
        terminator = data.find(b'\0', name, limit)
        if terminator < 0:
            raise InvalidPE('unterminated import DLL name')
        try:
            dll = data[name:terminator].decode('ascii')
        except UnicodeDecodeError as error:
            raise InvalidPE('non-ASCII import DLL name') from error
        if not re.fullmatch(r'[A-Za-z0-9_.-]+\.dll', dll, re.IGNORECASE):
            raise InvalidPE('invalid import DLL name')
        names.append(dll)
    raise InvalidPE('import descriptors lack a bounded terminator')


def check(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
        raise InvalidPE('unsupported executable input')
    names = imports(path.read_bytes())
    external = [name for name in names if re.match(r'^(vcruntime|msvcp|concrt|msvcr)\d.*\.dll$', name, re.IGNORECASE)]
    if external:
        raise InvalidPE('external Visual C++ runtime imports: ' + ', '.join(external))
    return {'file': path.name, 'direct_imports': names, 'external_vc_runtime_imports': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executables', nargs='+', type=Path)
    args = parser.parse_args()
    try:
        results = [check(path) for path in args.executables]
    except (InvalidPE, OSError) as error:
        parser.exit(1, f'Rust executable import gate failed: {error}\n')
    print(json.dumps({'status': 'rust_imports_verified', 'executables': results}))


if __name__ == '__main__':
    main()
