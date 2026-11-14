"""Exercise only a temporary staging fixture; never build/install/run an EXE."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1]/'stage.ps1'


def stage_fixture(source, relative=False):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        packaging = root/'packaging'
        scripts = packaging/'windows/scripts'
        scripts.mkdir(parents=True)
        (scripts/'fixture.ps1').write_text('# fixture')
        stage = packaging/'stage.ps1'; stage.write_text(source, encoding='utf-8')
        ui = root/'apps/desktop/dist'; ui.mkdir(parents=True)
        (ui/'index.html').write_text('fixture UI')
        output = root/'build-output'
        triple = 'x86_64-pc-windows-msvc'
        for directory, content in [(output/'release', b'WRONG stale host output'),
                                   (output/triple/'release', b'correct explicit-target output')]:
            directory.mkdir(parents=True)
            (directory/'lattice-service.exe').write_bytes(content)
        env = dict(os.environ, CARGO_TARGET_DIR='build-output' if relative else str(output), CARGO_BUILD_TARGET=triple)
        result = subprocess.run(['pwsh', '-NoProfile', '-File', str(stage), '-SkipRust', '-SkipUi'],
                                env=env, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError('Fixture staging failed: '+result.stderr)
        return (packaging/'dist/windows/bin/lattice-service.exe').read_bytes()


class StageTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell required for staging fixture')
    def test_explicit_target_and_absolute_target_dir(self):
        self.assertEqual(stage_fixture(SOURCE.read_text(encoding='utf-8')), b'correct explicit-target output')

    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell required for staging fixture')
    def test_explicit_target_and_relative_target_dir(self):
        self.assertEqual(stage_fixture(SOURCE.read_text(encoding='utf-8'), relative=True), b'correct explicit-target output')


if __name__ == '__main__':
    unittest.main()
