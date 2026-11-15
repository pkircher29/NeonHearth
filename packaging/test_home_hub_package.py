"""Packaging boundaries; synthetic payloads never launch a service or broker."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/package-home-hub.py'
spec = importlib.util.spec_from_file_location('package_home_hub', SCRIPT)
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ['target/release/NeonHearth.exe', 'target/release/lattice-service.exe',
                     'apps/desktop/dist/index.html', 'LICENSE', 'docs/owner/home-automation.md',
                     'docs/owner/traffic-monitor.md', 'docs/owner/network-monitor.md',
                     'crates/lattice-service/data/mac-assignments.json',
                     'mqtt/mosquitto.exe', 'mqtt/mosquitto_passwd.exe']:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'fixture')
        (self.root/'apps/desktop/package-lock.json').write_text('{"packages":{}}')
        (self.root/'Cargo.toml').write_text('[workspace.package]\nversion="0.1.0"\n')
        self.output = self.root / 'package'

    def run_package(self, *extra):
        with patch.object(package, 'ROOT', self.root), patch.object(sys, 'argv', [str(SCRIPT), '--mosquitto', str(self.root/'mqtt'), '--output', str(self.output), *extra]):
            def command(args, **kwargs):
                if args[:2] == ['git', 'rev-parse']:
                    return 'a' * 40
                if args[0] == 'git':
                    return ''
                return b'{"packages":[]}'
            with patch.object(package.subprocess, 'check_output', side_effect=command):
                package.main()

    def test_missing_broker_dependency_fails_without_partial_package(self):
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.run_package()
        self.assertFalse(self.output.exists(), 'Incomplete inputs must not leave a customer-looking package')

    def test_existing_archive_is_preserved_and_fails_before_output(self):
        archive = self.output.with_suffix('.zip')
        archive.write_bytes(b'existing release')
        with self.assertRaises(ValueError):
            self.run_package()
        self.assertFalse(self.output.exists())
        self.assertEqual(archive.read_bytes(), b'existing release')

    def test_dotted_release_name_keeps_full_version_in_archive_and_members(self):
        import zipfile
        self.complete_inputs()
        self.output = self.root/'NeonHearth-0.1.0-beta.1-windows-x64'
        self.run_package()
        archive = self.root/'NeonHearth-0.1.0-beta.1-windows-x64.zip'
        self.assertTrue(archive.is_file(), 'The published ZIP must retain the entire versioned folder name')
        self.assertFalse((self.root/'NeonHearth-0.1.0-beta.zip').exists())
        with zipfile.ZipFile(archive) as bundle:
            self.assertIn('NeonHearth-0.1.0-beta.1-windows-x64/NeonHearth.exe', bundle.namelist())

    def test_dotted_release_archive_is_preserved_before_creating_output(self):
        self.complete_inputs()
        self.output = self.root/'NeonHearth-0.1.0-beta.1-windows-x64'
        archive = self.root/'NeonHearth-0.1.0-beta.1-windows-x64.zip'
        archive.write_bytes(b'existing versioned release')
        with self.assertRaisesRegex(ValueError,'Archive already exists'):
            self.run_package()
        self.assertFalse(self.output.exists())
        self.assertEqual(archive.read_bytes(), b'existing versioned release')

    def complete_inputs(self):
        import hashlib
        for name in package.BROKER_FILES + package.BROKER_NOTICES:
            (self.root/'mqtt'/name).write_bytes(b'broker fixture')
        # Documentation is a required customer-facing component.
        (self.root/'docs/build').mkdir(parents=True)
        (self.root/'docs/build/windows-delivery.md').write_text('fixture delivery guide')
        (self.root/'mqtt/SOURCE-MANIFEST.json').write_text(json.dumps({**package.BROKER_SOURCE, 'file_sha256':{name:hashlib.sha256((self.root/'mqtt'/name).read_bytes()).hexdigest() for name in package.BROKER_FILES + package.BROKER_NOTICES}}))

    def test_complete_package_records_build_and_hashes_every_payload(self):
        import hashlib
        self.complete_inputs()
        self.run_package()
        info = json.loads((self.output/'BUILD-INFO.json').read_text())
        self.assertEqual(info['source_commit'], 'a'*40)
        self.assertEqual(info['version'], '0.1.0')
        manifest = json.loads((self.output/'PACKAGE-MANIFEST.json').read_text())
        self.assertEqual(manifest['format_version'], 1)
        rows = {row['path']:row for row in manifest['files']}
        for name in ['BUILD-INFO.json', 'NeonHearth.exe', 'bin/lattice-service.exe', 'ui/index.html', 'mqtt/mosquitto.exe']:
            content = (self.output/name).read_bytes()
            self.assertEqual(rows[name]['bytes'],len(content))
            self.assertEqual(rows[name]['sha256'],hashlib.sha256(content).hexdigest())
        self.assertNotIn('lattice.db', rows)

    def test_package_states_unsigned_unless_the_build_names_a_verified_signer(self):
        self.complete_inputs()
        self.run_package()
        info = json.loads((self.output/'BUILD-INFO.json').read_text())
        self.assertIs(info['unsigned'], True)
        self.assertNotIn('signed_by', info)
        self.assertIn('This development package is unsigned.', (self.output/'Read me.txt').read_text())

    def test_signed_package_records_the_publisher(self):
        self.complete_inputs()
        self.run_package('--signed-by', 'Example Publisher')
        info = json.loads((self.output/'BUILD-INFO.json').read_text())
        self.assertIs(info['unsigned'], False)
        self.assertEqual(info['signed_by'], 'Example Publisher')
        readme = (self.output/'Read me.txt').read_text()
        self.assertIn('code-signed by Example Publisher.', readme)
        self.assertNotIn('unsigned', readme)
        self.assertNotIn('{signing_note}', readme)

    def test_changed_broker_is_rejected_before_output(self):
        self.complete_inputs()
        (self.root/'mqtt/mosquitto.exe').write_bytes(b'tampered broker')
        with self.assertRaisesRegex(ValueError,'Broker component changed'):
            self.run_package()
        self.assertFalse(self.output.exists())

    def test_linked_local_and_nested_npm_notices_keep_names_and_patch_provenance(self):
        self.complete_inputs()
        local = self.root/'vendor/deepmerge'
        local.mkdir(parents=True)
        (local/'LICENSE').write_text('original license')
        (local/'PATCH.md').write_text('security patch provenance')
        nested = self.root/'apps/desktop/node_modules/outer/node_modules/inner'
        nested.mkdir(parents=True)
        (nested/'LICENSE').write_text('nested license')
        (self.root/'apps/desktop/package-lock.json').write_text(json.dumps({'packages':{
            '../../vendor/deepmerge':{'name':'@neonhearth/deepmerge','version':'4.3.1-patch.1','license':'MIT'},
            'node_modules/deepmerge':{'resolved':'../../vendor/deepmerge','link':True},
            'node_modules/outer/node_modules/inner':{'version':'1.0.0','license':'MIT'},
        }}))
        self.run_package()
        names = json.loads((self.output/'licenses/npm-components.json').read_text())
        self.assertEqual(json.loads((self.output/'BUILD-INFO.json').read_text())['version'],'0.1.0')
        self.assertIn('inner', [row['name'] for row in names])
        self.assertEqual((self.output/'licenses/npm/@neonhearth/deepmerge/4.3.1-patch.1/PATCH.md').read_text(), 'security patch provenance')
        self.assertEqual((self.output/'licenses/npm/inner/1.0.0/LICENSE').read_text(),'nested license')


if __name__ == '__main__':
    unittest.main()
