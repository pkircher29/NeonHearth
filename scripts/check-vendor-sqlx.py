#!/usr/bin/env python3
"""Prove vendor/sqlx-sqlite is the pinned upstream crate plus ONLY the documented change.

Fetches sqlx-sqlite from crates.io, checks its SHA-256 against the checksum
recorded in vendor/sqlx-sqlite/NEONHEARTH-PATCH.md (Cargo.lock cannot carry one:
a [patch] path dependency has no registry checksum), unpacks it, and compares
every file with the vendored copy. Allowed differences, and nothing else:

  * Cargo.toml: exactly the `libsqlite3-sys` version line (0.30.1 -> 0.39.1)
  * Cargo.toml.orig is upstream's own file and must be byte-identical
  * NEONHEARTH-PATCH.md: the added note
  * .cargo_vcs_info.json is compared like any other file

Run in CI (no network is needed with --crate pointing at a downloaded file).
"""
import argparse
import hashlib
import io
import re
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / 'vendor' / 'sqlx-sqlite'
ADDED = {'NEONHEARTH-PATCH.md'}
NAME_VERSION = 'sqlx-sqlite-0.8.6'
URL = f'https://static.crates.io/crates/sqlx-sqlite/{NAME_VERSION}.crate'


def documented_checksum():
    notes = (VENDOR / 'NEONHEARTH-PATCH.md').read_text(encoding='utf-8')
    match = re.search(r'SHA-256 `([0-9a-f]{64})`', notes)
    if not match:
        raise ValueError('NEONHEARTH-PATCH.md does not record the upstream SHA-256')
    return match.group(1)


def upstream_files(data):
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive.getmembers():
            if not member.isfile():
                if member.isdir():
                    continue
                raise ValueError(f'Unexpected archive member type: {member.name}')
            name = member.name
            prefix = NAME_VERSION + '/'
            if not name.startswith(prefix) or '..' in name.split('/'):
                raise ValueError(f'Unexpected archive member: {name}')
            files[name[len(prefix):]] = archive.extractfile(member).read()
    return files


def vendored_files():
    files = {}
    for path in sorted(VENDOR.rglob('*')):
        if path.is_file():
            files[path.relative_to(VENDOR).as_posix()] = path.read_bytes()
    return files


def normalise(data):
    return data.replace(b'\r\n', b'\n')


def compare(upstream, vendored):
    problems = []
    for name in sorted(set(upstream) | set(vendored)):
        if name in ADDED and name not in upstream:
            continue
        if name == 'Cargo.toml':
            expected = normalise(upstream.get(name, b'')).decode('utf-8')
            actual = normalise(vendored.get(name, b'')).decode('utf-8')
            patched = re.sub(r'(\[dependencies\.libsqlite3-sys\]\nversion = )"0\.30\.1"', r'\1"0.39.1"', expected, count=1)
            if patched == expected or actual != patched:
                problems.append('Cargo.toml differs from upstream by more than the libsqlite3-sys version pin')
            continue
        if name not in vendored:
            problems.append(f'missing from vendor: {name}')
        elif name not in upstream:
            problems.append(f'not in upstream: {name}')
        elif normalise(vendored[name]) != normalise(upstream[name]):
            problems.append(f'modified: {name}')
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--crate', type=Path, help='Use an already downloaded .crate (still checksum-verified)')
    args = parser.parse_args(argv)
    expected = documented_checksum()
    if args.crate:
        data = args.crate.read_bytes()
    else:
        with urllib.request.urlopen(URL, timeout=60) as response:
            data = response.read(64 * 1024 * 1024)
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        print(f'Upstream checksum mismatch: documented {expected}, downloaded {actual}', file=sys.stderr)
        return 1
    problems = compare(upstream_files(data), vendored_files())
    for problem in problems:
        print('vendor/sqlx-sqlite: ' + problem, file=sys.stderr)
    if problems:
        return 1
    print('vendor/sqlx-sqlite matches upstream 0.8.6 plus the documented libsqlite3-sys pin')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
