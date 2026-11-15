#!/usr/bin/env python3
"""Hash lists that carry release artifacts between CI jobs.

`create DIR` writes DIR/SHA256SUMS (sorted `hash  relative/path` lines, covering
every file below DIR except SHA256SUMS itself) and prints the SHA-256 of that
list. The producing job publishes that value as a job output.

`verify DIR --expect VALUE` is run by every consuming job. It fails unless the
list's own hash equals VALUE (which arrived through `needs.<job>.outputs`, a
different channel from the artifact store), every listed file matches, and DIR
holds no file that the list does not name. Only the Python standard library is
used, so jobs that hold signing credentials can run it.
"""
import argparse
import hashlib
import re
import sys
from pathlib import Path

LIST_NAME = 'SHA256SUMS'
LINE = re.compile(r'^([0-9a-f]{64})  (\S.*)$')


def digest(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def members(root):
    found = []
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError(f'Links are not accepted: {path.name}')
        if path.is_file() and path.relative_to(root).as_posix() != LIST_NAME:
            found.append(path)
    return found


def create(root):
    root = Path(root)
    if not root.is_dir():
        raise ValueError('Directory not found')
    lines = [f'{digest(path)}  {path.relative_to(root).as_posix()}\n' for path in members(root)]
    if not lines:
        raise ValueError('Refusing to publish an empty file list')
    (root / LIST_NAME).write_text(''.join(lines), encoding='utf-8', newline='\n')
    return digest(root / LIST_NAME)


def verify(root, expected):
    root = Path(root)
    listing = root / LIST_NAME
    if not re.fullmatch(r'[0-9a-f]{64}', expected or ''):
        raise ValueError('The expected hash from the producing job is missing or malformed')
    if not listing.is_file() or listing.is_symlink():
        raise ValueError('The artifact has no SHA256SUMS list')
    if digest(listing) != expected:
        raise ValueError('SHA256SUMS does not match the hash published by the producing job')
    listed = {}
    for line in listing.read_text(encoding='utf-8').splitlines():
        match = LINE.match(line)
        if not match:
            raise ValueError('Malformed SHA256SUMS line')
        name = match.group(2)
        if name in listed or name.startswith('/') or '..' in name.split('/') or '\\' in name or ':' in name:
            raise ValueError('Unsafe or repeated name in SHA256SUMS')
        listed[name] = match.group(1)
    actual = {path.relative_to(root).as_posix(): path for path in members(root)}
    if set(actual) != set(listed):
        extra = sorted(set(actual) - set(listed))
        missing = sorted(set(listed) - set(actual))
        raise ValueError(f'Artifact contents differ from the list. Unlisted: {extra}. Missing: {missing}')
    for name, path in actual.items():
        if digest(path) != listed[name]:
            raise ValueError(f'Hash mismatch: {name}')
    return len(listed)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('create').add_argument('directory')
    check = sub.add_parser('verify')
    check.add_argument('directory')
    check.add_argument('--expect', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'create':
            print(create(args.directory))
        else:
            count = verify(args.directory, args.expect)
            print(f'verified {count} files')
    except (ValueError, OSError) as error:
        print(f'ci-hashes: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
