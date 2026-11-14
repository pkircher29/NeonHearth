#!/usr/bin/env python3
"""Assemble a clean, relocatable Windows Home Hub folder. Never include runtime data."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BROKER_SOURCE = json.loads((ROOT/'packaging/windows/mosquitto-source.json').read_text(encoding='utf-8'))
BROKER_FILES = BROKER_SOURCE['files']
BROKER_NOTICES = BROKER_SOURCE['notices']


def digest(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=ROOT / 'target' / 'release')
    parser.add_argument('--mosquitto', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version', help='Release tag version without v; defaults to Cargo workspace version')
    parser.add_argument('--signed-by', help='Publisher whose code signature the build already verified on NeonHearth.exe and lattice-service.exe; omit for an unsigned package')
    args = parser.parse_args()
    output = args.output.resolve()
    archive = output.with_name(output.name + '.zip')
    if output.exists():
        raise ValueError('Choose a new empty package destination; existing packages are preserved')
    if archive.exists():
        raise ValueError('Archive already exists')
    ui = ROOT / 'apps' / 'desktop' / 'dist'
    inputs = [args.target / 'NeonHearth.exe', args.target / 'lattice-service.exe', ui / 'index.html', ROOT / 'LICENSE']
    inputs += [args.mosquitto / name for name in BROKER_FILES + BROKER_NOTICES]
    inputs += [ROOT / name for name in ['docs/owner/home-automation.md', 'docs/owner/traffic-monitor.md', 'docs/owner/network-monitor.md', 'docs/build/windows-delivery.md', 'crates/lattice-service/data/mac-assignments.json']]
    for path in inputs:
        if not path.is_file() or path.is_symlink():
            raise ValueError(f'Build or supply the required component: {path.name}')
    broker = json.loads((args.mosquitto/'SOURCE-MANIFEST.json').read_text(encoding='utf-8'))
    if broker.get('sha256') != BROKER_SOURCE['sha256'] or broker.get('version') != BROKER_SOURCE['version']:
        raise ValueError('Prepare the pinned broker with packaging/windows/prepare-mosquitto.py')
    for name in BROKER_FILES + BROKER_NOTICES:
        if broker.get('file_sha256', {}).get(name) != digest(args.mosquitto/name):
            raise ValueError('Broker component changed: '+name)
    version = args.version or tomllib.loads((ROOT / 'Cargo.toml').read_text(encoding='utf-8'))['workspace']['package']['version']
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', version):
        raise ValueError('Invalid package version')
    source_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if not re.fullmatch(r'[0-9a-f]{40}', source_commit):
        raise ValueError('Could not identify the source commit')
    source_dirty = bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip())
    # Resolve metadata before writing a customer-looking package directory.
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--format-version', '1', '--locked'], cwd=ROOT))
    lock = json.loads((ROOT / 'apps/desktop/package-lock.json').read_text(encoding='utf-8'))
    output.mkdir(parents=True)
    def copy(source, destination):
        target = output / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    copy(args.target / 'NeonHearth.exe', 'NeonHearth.exe')
    copy(args.target / 'lattice-service.exe', 'bin/lattice-service.exe')
    shutil.copytree(ui, output / 'ui')
    for name in BROKER_FILES:
        copy(args.mosquitto / name, 'mqtt/' + name)
    for name in BROKER_NOTICES:
        copy(args.mosquitto / name, 'licenses/mosquitto/' + name)
    for name in ['LICENSE', 'docs/owner/home-automation.md']:
        copy(ROOT / name, 'licenses/NeonHearth.txt' if name == 'LICENSE' else 'Home automation.md')
    copy(ROOT / 'docs/owner/traffic-monitor.md', 'Traffic and devices.md')
    copy(ROOT / 'docs/owner/network-monitor.md', 'network-monitor.md')
    copy(ROOT / 'docs/build/windows-delivery.md', 'Windows delivery.md')
    copy(args.mosquitto/'SOURCE-MANIFEST.json', 'licenses/mosquitto/SOURCE-MANIFEST.json')
    copy(ROOT / 'crates/lattice-service/data/mac-assignments.json', 'licenses/ieee-assignment-sources.json')
    # Include dependency notices from the installed, locked source trees.
    packages = []
    for package in metadata['packages']:
        packages.append({key:package.get(key) for key in ['name','version','license','repository']})
        directory = Path(package['manifest_path']).parent
        for path in directory.iterdir():
            if path.is_file() and (path.name.upper().startswith(('LICENSE','COPYING','NOTICE')) or path.name == 'NEONHEARTH-PATCH.md') and path.stat().st_size <= 256 * 1024:
                copy(path, f"licenses/rust/{package['name']}-{package['version']}/{path.name}")
    (output / 'licenses' / 'rust-components.json').write_text(json.dumps(packages,indent=2),encoding='utf-8')
    packages = []
    for location, package in lock['packages'].items():
        if not location:
            continue
        source = package.get('resolved', location) if package.get('link') else location
        info = lock['packages'].get(source, package) if package.get('link') else package
        directory = (ROOT / 'apps/desktop' / source).resolve()
        name = info.get('name') or location.rsplit('node_modules/',1)[-1]
        component_version = info.get('version') or 'unversioned'
        if not re.fullmatch(r'(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+', name) or name in ('.','..'):
            raise ValueError('Unsupported npm component name: '+name)
        if not isinstance(component_version,str) or not re.fullmatch(r'[A-Za-z0-9_.+-]+',component_version) or component_version in ('.','..'):
            raise ValueError('Unsupported npm component version')
        packages.append({'name':name,'version':component_version,'license':info.get('license'),'integrity':info.get('integrity'), 'source':source})
        if directory.is_dir():
            for path in directory.iterdir():
                if path.is_file() and (path.name.upper().startswith(('LICENSE','COPYING','NOTICE','OFL')) or path.name == 'PATCH.md') and path.stat().st_size <= 256 * 1024:
                    copy(path, f"licenses/npm/{name}/{component_version}/{path.name}")
    (output / 'licenses' / 'npm-components.json').write_text(json.dumps(packages,indent=2),encoding='utf-8')
    (output / 'BUILD-INFO.json').write_text(json.dumps({'format_version':1, 'source_commit':source_commit,
        'source_dirty':source_dirty, 'version':version, 'platform':'windows-x64', 'delivery':'portable-home-hub',
        'unsigned':not args.signed_by, **({'signed_by':args.signed_by} if args.signed_by else {}), 'broker':{'name':'mosquitto', 'version':BROKER_SOURCE['version'],
        'installer_sha256':BROKER_SOURCE['sha256']}}, indent=2), encoding='utf-8')
    signing_note = (f'NeonHearth.exe and bin/lattice-service.exe are code-signed by {args.signed_by}.'
                    if args.signed_by else 'This development package is unsigned.')
    (output / 'Read me.txt').write_text('''NeonHearth Home Hub for Windows x64

Open NeonHearth.exe. The launcher starts the local collector and authenticated MQTT hub, then opens your browser.
No Python, Node, administrator account, or packet-capture driver is required by the launcher.
If an older NeonHearth Windows service is installed, keep using its dashboard until you have
backed up its database and deliberately stopped that service. Do not run both collectors.
The legacy service's ProgramData database and this per-user hub are separate; this package
does not silently import or delete either database. See Windows delivery.md for switching.
Mosquitto requires the Microsoft Visual C++ v14 Redistributable (x64). If startup reports a missing DLL (0xC0000135), install or repair this Microsoft prerequisite, then open NeonHearth again:
https://aka.ms/vc14/vc_redist.x64.exe
Windows may require administrator approval for this prerequisite. Your NeonHearth data is preserved. Microsoft instructions:
https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist

Private per-user state is stored in %LOCALAPPDATA%\\NeonHearthHomeHub. The owner token is protected with Windows DPAPI.
The dashboard uses http://127.0.0.1:58121; MQTT uses 127.0.0.1:58183. The launcher refuses unrelated listeners on those ports.
Run NeonHearth.exe --status to check this instance; --stop stops its verified processes and preserves its data.
Keep the complete package folder together. Extract a new version to a new folder after stopping the old version.
PACKAGE-MANIFEST.json detects missing or damaged components. {signing_note}

Devices > Identify devices with a network scan starts bounded discovery across observed devices.
Traffic opens on Entire network: all observed devices and a configurable Predator Connect W6 household WAN graph.
Use Discover devices now to find previously unseen LAN devices. Network preferences enables periodic discovery and the W6 read-only feed.
This computer > applications shows local programs, connections, usage history, and alerts. See network-monitor.md and Traffic and devices.md for coverage and OS permission requirements.
Devices and Guard support owner-confirmed names and links to observed web ports. Naming a device does not approve network access.
Home > Measurement units selects meters or feet/inches. Copy footprint transfers geometry to a new or empty floor.
Automation connects Home Assistant and enables individual approved light/switch controls.
CDP and LLDP require an Ethernet PCAP from the relevant link. Avahi integration is available in the Linux service.

Source and license: https://github.com/pkircher29/NeonHearth (AGPL-3.0-or-later)
Mosquitto: https://github.com/eclipse-mosquitto/mosquitto/tree/v2.1.2 (BSD-3-Clause or EPL-2.0)
Third-party notices are in licenses/.
'''.replace('{signing_note}', signing_note),encoding='utf-8')
    files = []
    for path in sorted(output.rglob('*')):
        if path.is_file():
            if path.is_symlink() or path.stat().st_size > 128 * 1024 * 1024:
                raise ValueError('Unsupported package member')
            files.append({'path':path.relative_to(output).as_posix(),'bytes':path.stat().st_size,'sha256':digest(path)})
    if len(files)>4096:
        raise ValueError('Package manifest exceeds the launcher limit')
    (output / 'PACKAGE-MANIFEST.json').write_text(json.dumps({'format_version':1,'files':files},indent=2),encoding='utf-8')
    # Dependency archives can carry Unix-epoch timestamps, outside ZIP's range.
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6,strict_timestamps=False) as bundle:
        for path in sorted(output.rglob('*')):
            if path.is_file(): bundle.write(path,path.relative_to(output.parent))
    print(json.dumps({'package':str(output),'archive':str(archive),'files':len(files),'sha256':digest(archive)}))

if __name__ == '__main__':
    main()
