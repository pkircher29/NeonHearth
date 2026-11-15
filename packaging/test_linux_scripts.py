"""Behavioural tests for the deb/rpm maintainer scripts (run under a POSIX sh).

The scripts hard-code absolute system paths, so each test runs a copy with those
paths redirected into a temporary directory, with stub `systemctl`, `chown`,
`getent` and `systemd-sysusers` programs that record what they were asked to do.
"""
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent / 'linux' / 'scripts'
# Obviously fake values; never a real token.
FAKE_SEED = 'fakeSeedToken0123456789abcdefghijklmnopqrstuvwxyzAB'
FAKE_ROTATED = 'fake-rotated-token-0123456789-ABCDEFGHIJ'
SH = shutil.which('sh')


@unittest.skipUnless(SH, 'a POSIX sh is required')
class MaintainerScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.log = self.root / 'calls.log'
        self.systemd = self.root / 'run-systemd'
        self.systemd.mkdir()
        self.etc = self.root / 'etc-neonhearth'
        self.state = self.root / 'var-lib-neonhearth'
        self.state.mkdir()
        for name, body in {
            'systemctl': 'echo "systemctl $*" >> "$CALLS"\n[ "$1" = is-enabled ] && exit "${IS_ENABLED:-0}"\nexit 0\n',
            'chown': 'echo "chown $*" >> "$CALLS"\n',
            'getent': 'exit 0\n',
            'systemd-sysusers': 'exit 0\n',
            'id': 'echo "${FAKE_UID:-0}"\n',
        }.items():
            path = self.bin / name
            path.write_text('#!/bin/sh\n' + body, newline='\n')
            path.chmod(path.stat().st_mode | stat.S_IEXEC)

    def run_script(self, name, *args, enabled=0):
        text = (SCRIPTS / name).read_text(encoding='utf-8')
        text = text.replace('/run/systemd/system', str(self.systemd).replace('\\', '/'))
        text = text.replace('ENV_DIR=/etc/neonhearth', f'ENV_DIR={str(self.etc).replace(chr(92), "/")}')
        text = text.replace('STATE_DIR=/var/lib/neonhearth', f'STATE_DIR={str(self.state).replace(chr(92), "/")}')
        text = text.replace('ENV_FILE=/etc/neonhearth/service.env', f'ENV_FILE={str(self.etc / "service.env").replace(chr(92), "/")}')
        script = self.root / name
        script.write_text(text, newline='\n')
        env = {**os.environ, 'PATH': f'{self.bin}{os.pathsep}{os.environ["PATH"]}', 'CALLS': str(self.log), 'IS_ENABLED': str(enabled)}
        return subprocess.run([SH, str(script), *args], capture_output=True, text=True, env=env)

    def run_helper(self, uid='0'):
        return self.run_script_path(SCRIPTS.parent / 'neonhearth-token', FAKE_UID=uid)

    def run_script_path(self, source, **extra):
        text = source.read_text(encoding='utf-8')
        text = text.replace('STATE_DIR=/var/lib/neonhearth', f'STATE_DIR={str(self.state).replace(chr(92), "/")}')
        text = text.replace('ENV_FILE=/etc/neonhearth/service.env', f'ENV_FILE={str(self.etc / "service.env").replace(chr(92), "/")}')
        script = self.root / source.name
        script.write_text(text, newline='\n')
        env = {**os.environ, 'PATH': f'{self.bin}{os.pathsep}{os.environ["PATH"]}', 'CALLS': str(self.log), **extra}
        return subprocess.run([SH, str(script)], capture_output=True, text=True, env=env)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_upgrade_does_not_stop_or_disable_the_unit(self):
        for args in (('upgrade',), ('1',), ('failed-upgrade',), ('deconfigure',)):
            self.log.write_text('')
            result = self.run_script('preremove.sh', *args)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.calls(), [], f'preremove {args} must leave the unit alone')

    def test_real_removal_stops_and_disables(self):
        for args in (('remove',), ('0',)):
            self.log.write_text('')
            self.assertEqual(self.run_script('preremove.sh', *args).returncode, 0)
            self.assertEqual(self.calls(), ['systemctl stop neonhearth.service', 'systemctl disable neonhearth.service'])

    def test_real_removal_deletes_the_rotated_token_but_keeps_other_state(self):
        for args in (('remove',), ('0',)):
            (self.state / 'owner-token').write_text(FAKE_ROTATED)
            (self.state / 'lattice.db').write_text('database')
            self.assertEqual(self.run_script('preremove.sh', *args).returncode, 0)
            self.assertFalse((self.state / 'owner-token').exists(), args)
            self.assertEqual((self.state / 'lattice.db').read_text(), 'database')
        # Removing when there is no token file is not an error.
        self.assertEqual(self.run_script('preremove.sh', 'remove').returncode, 0)

    def test_upgrade_keeps_the_rotated_token_file(self):
        (self.state / 'owner-token').write_text(FAKE_ROTATED)
        for args in (('upgrade',), ('1',)):
            self.assertEqual(self.run_script('preremove.sh', *args).returncode, 0)
        self.run_script('postinstall.sh', 'configure')  # fresh: creates env, drops stale file
        (self.state / 'owner-token').write_text(FAKE_ROTATED)
        self.assertEqual(self.run_script('postinstall.sh', 'configure', '1.0.0').returncode, 0)
        self.assertEqual((self.state / 'owner-token').read_text(), FAKE_ROTATED)

    def test_fresh_install_drops_a_stale_rotated_token_so_the_new_seed_applies(self):
        (self.state / 'owner-token').write_text(FAKE_ROTATED)
        self.assertEqual(self.run_script('postinstall.sh', 'configure').returncode, 0)
        self.assertFalse((self.state / 'owner-token').exists())

    def test_helper_prefers_the_rotated_token_file_and_trims_it(self):
        self.etc.mkdir()
        (self.etc / 'service.env').write_text(f'LATTICE_SERVICE_TOKEN={FAKE_SEED}\n')
        result = self.run_helper()
        self.assertEqual((result.returncode, result.stdout.strip()), (0, FAKE_SEED), result.stderr)
        (self.state / 'owner-token').write_text(f'  {FAKE_ROTATED}\r\n')
        result = self.run_helper()
        self.assertEqual((result.returncode, result.stdout.strip()), (0, FAKE_ROTATED), result.stderr)
        # An empty file is ignored, as the service does.
        (self.state / 'owner-token').write_text('\n')
        self.assertEqual(self.run_helper().stdout.strip(), FAKE_SEED)

    def test_helper_refuses_non_root_malformed_and_missing(self):
        self.etc.mkdir()
        self.assertNotEqual(self.run_helper(uid='1000').returncode, 0)
        self.assertNotEqual(self.run_helper().returncode, 0)  # no env file, no token file
        (self.etc / 'service.env').write_text('LATTICE_SERVICE_TOKEN=short\n')
        self.assertNotEqual(self.run_helper().returncode, 0)
        (self.state / 'owner-token').write_text('has space inside it ' + 'x' * 30)
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('x' * 30, result.stderr)

    def test_fresh_install_creates_token_enables_and_starts(self):
        result = self.run_script('postinstall.sh', 'configure')
        self.assertEqual(result.returncode, 0, result.stderr)
        env_file = self.etc / 'service.env'
        text = env_file.read_text()
        self.assertRegex(text, r'^LATTICE_SERVICE_TOKEN=[A-Za-z0-9]{64}\n$')
        calls = self.calls()
        self.assertIn('systemctl enable neonhearth.service', calls)
        self.assertIn('systemctl restart neonhearth.service', calls)
        self.assertIn('chown root:root ' + str(env_file).replace(chr(92), '/'), calls)
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(env_file.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.etc.stat().st_mode), 0o700)

    def test_upgrade_keeps_token_does_not_reenable_and_restarts_only_if_enabled(self):
        self.run_script('postinstall.sh', 'configure')
        token = (self.etc / 'service.env').read_text()
        self.log.write_text('')
        self.run_script('postinstall.sh', 'configure', '1.0.0', enabled=0)
        self.assertEqual((self.etc / 'service.env').read_text(), token)
        calls = self.calls()
        self.assertNotIn('systemctl enable neonhearth.service', calls)
        self.assertIn('systemctl restart neonhearth.service', calls)
        # An administrator-disabled unit stays stopped across the upgrade.
        self.log.write_text('')
        self.run_script('postinstall.sh', '2', enabled=1)
        self.assertNotIn('systemctl restart neonhearth.service', self.calls())

    @unittest.skipIf(os.name == 'nt', 'POSIX permission bits')
    def test_older_world_group_readable_token_file_is_tightened(self):
        self.etc.mkdir()
        env_file = self.etc / 'service.env'
        env_file.write_text('LATTICE_SERVICE_TOKEN=' + 'a' * 64 + '\n')
        env_file.chmod(0o640)
        self.etc.chmod(0o755)
        self.assertEqual(self.run_script('postinstall.sh', 'configure', '0.9.0').returncode, 0)
        self.assertEqual(stat.S_IMODE(env_file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.etc.stat().st_mode), 0o700)

    @unittest.skipIf(os.name == 'nt', 'symlinks need privileges on Windows')
    def test_symlinked_token_file_is_refused(self):
        self.etc.mkdir()
        target = self.root / 'elsewhere'
        target.write_text('x')
        (self.etc / 'service.env').symlink_to(target)
        result = self.run_script('postinstall.sh', 'configure', '0.9.0')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(), 'x')

    def test_postinstall_never_writes_into_the_service_state_directory(self):
        text = (SCRIPTS / 'postinstall.sh').read_text(encoding='utf-8')
        code = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
        self.assertNotRegex(code, r'[>]+\s*"?/var/lib')
        self.assertNotIn('cat >', code)
        self.assertNotIn('README-UNINSTALL', code)

    def test_every_script_parses_and_stage_uses_locked(self):
        for script in [*SCRIPTS.glob('*.sh'), SCRIPTS.parent / 'neonhearth-token']:
            self.assertEqual(subprocess.run([SH, '-n', str(script)], capture_output=True).returncode, 0, script.name)
        stage = (SCRIPTS.parents[1] / 'stage.sh').read_text(encoding='utf-8')
        self.assertIn('cargo build --locked --release', stage)
        self.assertNotIn('if true;', stage)


if __name__ == '__main__':
    unittest.main()
