#!/usr/bin/env python3
"""Assemble a clean, relocatable Windows Home Hub folder. Never include runtime data."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=ROOT / 'target' / 'release')
    parser.add_argument('--mosquitto', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise ValueError('Choose a new empty package destination; existing packages are preserved')
    ui = ROOT / 'apps' / 'desktop' / 'dist'
    for path in [args.target / 'NeonHearth.exe', args.target / 'lattice-service.exe', ui / 'index.html', args.mosquitto / 'mosquitto.exe', args.mosquitto / 'mosquitto_passwd.exe', ROOT / 'LICENSE']:
        if not path.is_file():
            raise ValueError(f'Build or supply the required component: {path.name}')
    output.mkdir(parents=True)
    def copy(source, destination):
        target = output / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    copy(args.target / 'NeonHearth.exe', 'NeonHearth.exe')
    copy(args.target / 'lattice-service.exe', 'bin/lattice-service.exe')
    shutil.copytree(ui, output / 'ui')
    for name in ['mosquitto.exe', 'mosquitto_passwd.exe', 'mosquitto_pub.exe', 'mosquitto_sub.exe',
                 'mosquitto_common.dll', 'mosquitto.dll', 'mosquitto_acl_file.dll', 'mosquitto_password_file.dll',
                 'libssl-3-x64.dll', 'libcrypto-3-x64.dll', 'libmicrohttpd-dll.dll', 'cjson.dll', 'pthreadVC3.dll']:
        copy(args.mosquitto / name, 'mqtt/' + name)
    for name in ['NOTICE.md', 'edl-v10', 'epl-v20', 'README-windows.txt']:
        copy(args.mosquitto / name, 'licenses/mosquitto/' + name)
    for name in ['LICENSE', 'docs/owner/home-automation.md']:
        copy(ROOT / name, 'licenses/NeonHearth.txt' if name == 'LICENSE' else 'Home automation.md')
    copy(ROOT / 'docs/owner/traffic-monitor.md', 'Traffic and devices.md')
    copy(ROOT / 'docs/owner/network-monitor.md', 'network-monitor.md')
    copy(ROOT / 'crates/lattice-service/data/mac-assignments.json', 'licenses/ieee-assignment-sources.json')
    # Include dependency notices from the installed, locked source trees.
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--format-version', '1', '--locked'], cwd=ROOT))
    packages = []
    for package in metadata['packages']:
        packages.append({key:package.get(key) for key in ['name','version','license','repository']})
        directory = Path(package['manifest_path']).parent
        for path in directory.iterdir():
            if path.is_file() and path.name.upper().startswith(('LICENSE','COPYING','NOTICE')) and path.stat().st_size <= 256 * 1024:
                copy(path, f"licenses/rust/{package['name']}-{package['version']}/{path.name}")
    (output / 'licenses' / 'rust-components.json').write_text(json.dumps(packages,indent=2),encoding='utf-8')
    lock = json.loads((ROOT / 'apps/desktop/package-lock.json').read_text(encoding='utf-8'))
    packages = []
    for location, package in lock['packages'].items():
        if not location:
            continue
        directory = ROOT / 'apps/desktop' / location
        packages.append({'name':location.removeprefix('node_modules/'),'version':package.get('version'),'license':package.get('license'),'integrity':package.get('integrity')})
        if directory.is_dir():
            for path in directory.iterdir():
                if path.is_file() and path.name.upper().startswith(('LICENSE','COPYING','NOTICE','OFL')) and path.stat().st_size <= 256 * 1024:
                    copy(path, f"licenses/npm/{location.removeprefix('node_modules/')}/{path.name}")
    (output / 'licenses' / 'npm-components.json').write_text(json.dumps(packages,indent=2),encoding='utf-8')
    (output / 'Read me.txt').write_text('''NeonHearth Home Hub for Windows x64

Open NeonHearth.exe. The launcher starts the local collector and authenticated MQTT hub, then opens your browser.
No Python, Node, administrator account, or packet-capture driver is required by the launcher.
Mosquitto requires the Microsoft Visual C++ 2015-2022 x64 runtime. If Windows reports VCRUNTIME140.dll missing, install it from Microsoft:
https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist

Private per-user state is stored in %LOCALAPPDATA%\\NeonHearthHomeHub. The owner token is protected with Windows DPAPI.
The dashboard uses http://127.0.0.1:58121; MQTT uses 127.0.0.1:58183. The launcher refuses unrelated listeners on those ports.
Run NeonHearth.exe --status to check this instance; --stop stops its verified processes and preserves its data.
Keep the complete package folder together. Extract a new version to a new folder after stopping the old version.
PACKAGE-MANIFEST.json detects missing or damaged components. This development package is unsigned.

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
''',encoding='utf-8')
    files = []
    for path in sorted(output.rglob('*')):
        if path.is_file():
            if path.is_symlink() or path.stat().st_size > 128 * 1024 * 1024:
                raise ValueError('Unsupported package member')
            files.append({'path':path.relative_to(output).as_posix(),'bytes':path.stat().st_size,'sha256':hashlib.file_digest(path.open('rb'),'sha256').hexdigest()})
    if len(files)>4096:
        raise ValueError('Package manifest exceeds the launcher limit')
    (output / 'PACKAGE-MANIFEST.json').write_text(json.dumps({'format_version':1,'files':files},indent=2),encoding='utf-8')
    archive = output.with_suffix('.zip')
    if archive.exists():
        raise ValueError('Archive already exists')
    # Dependency archives can carry Unix-epoch timestamps, outside ZIP's range.
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6,strict_timestamps=False) as bundle:
        for path in sorted(output.rglob('*')):
            if path.is_file(): bundle.write(path,path.relative_to(output.parent))
    print(json.dumps({'package':str(output),'archive':str(archive),'files':len(files),'sha256':hashlib.file_digest(archive.open('rb'),'sha256').hexdigest()}))

if __name__ == '__main__':
    main()
