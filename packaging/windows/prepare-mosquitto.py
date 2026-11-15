"""Verify and extract the pinned broker payload. Never execute its installer."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request

SOURCE = json.loads(Path(__file__).with_name('mosquitto-source.json').read_text(encoding='utf-8'))


def digest(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--archive', type=Path, help='Optional already downloaded installer; still checksum-verified')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise ValueError('Choose a new broker destination; existing folders are preserved')
    seven = shutil.which('7z') or 'C:/Program Files/7-Zip/7z.exe'
    with tempfile.TemporaryDirectory(prefix='neonhearth-broker-') as temporary:
        work = Path(temporary)
        archive = args.archive
        if archive is None:
            archive = work / 'mosquitto-installer.exe'
            with urllib.request.urlopen(SOURCE['url'], timeout=60) as response, archive.open('wb') as target:
                shutil.copyfileobj(response, target)
        if digest(archive) != SOURCE['sha256']:
            raise ValueError('Mosquitto installer SHA-256 does not match the pinned source')
        extracted = work / 'extracted'
        members = SOURCE['files'] + SOURCE['notices']
        subprocess.run([seven, 'x', str(archive), '-o'+str(extracted), '-y', *members], check=True, stdout=subprocess.DEVNULL)
        files = {}
        for name in members:
            path = extracted / name
            if not path.is_file() or path.is_symlink():
                raise ValueError('Pinned broker archive is missing '+name)
            files[name] = digest(path)
        output.mkdir(parents=True)
        for name in members:
            shutil.copy2(extracted / name, output / name)
        (output/'SOURCE-MANIFEST.json').write_text(json.dumps({**SOURCE, 'file_sha256':files}, indent=2), encoding='utf-8')
    print(json.dumps({'output':str(output), 'version':SOURCE['version'], 'installer_sha256':SOURCE['sha256'], 'installer_executed':False}))


if __name__ == '__main__':
    main()
