r"""Static contract tests for the Windows installer's owner-token hand-off.

Nothing here installs or runs the service. It pins the facts the launcher
relies on: the installer writes <ProgramData>NeonHearth\owner-token (the file
the service reads before any environment value), keeps the PowerShell 5.1 and
alphabet constraints, removes the file only on a real uninstall, and the
Start-menu script reads the file first.
"""
import re
import shutil
import subprocess
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

WINDOWS = Path(__file__).resolve().parent
CONFIGURE = (WINDOWS / 'scripts' / 'configure-service.ps1').read_text(encoding='utf-8')
OPEN = (WINDOWS / 'scripts' / 'open-neonhearth.ps1').read_text(encoding='utf-8')
WXS = (WINDOWS / 'NeonHearth.wxs').read_text(encoding='utf-8')


def code(text):
    return '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))


class OwnerTokenInstallerContract(unittest.TestCase):
    def test_configure_writes_the_token_file_the_service_reads(self):
        body = code(CONFIGURE)
        self.assertIn("Join-Path $stateDir 'owner-token'", body)
        self.assertIn('Write-OwnerTokenFile', body)
        # Never overwrite a rotated token that is already on disk.
        self.assertRegex(body, r'Read-OwnerTokenFile -Path \$tokenFile')
        self.assertIn('preserved', CONFIGURE)

    def test_registry_copy_is_removed_and_never_written_back(self):
        body = code(CONFIGURE)
        self.assertNotRegex(body, r'\$entries\.Add\("LATTICE_SERVICE_TOKEN=')
        self.assertIn("-notlike 'LATTICE_SERVICE_TOKEN=*'", body)

    def test_powershell_51_compatible_url_safe_token(self):
        body = code(CONFIGURE)
        self.assertNotIn('.Fill(', body)
        self.assertIn('RandomNumberGenerator]::Create()', body)
        self.assertIn(".Replace('+', '-').Replace('/', '_')", body)
        self.assertIn('{32,}', body)  # same minimum length as the service

    def test_token_is_never_printed(self):
        for line in CONFIGURE.splitlines():
            if re.search(r'Write-(Log|Host)', line):
                self.assertNotRegex(line, r'\$(token|legacyToken|fileToken|Value)\b', line)

    def test_launcher_script_reads_the_file_before_the_registry_value(self):
        body = code(OPEN)
        self.assertIn(r"'NeonHearth\owner-token'", body)
        self.assertLess(body.index("LATTICE_SERVICE_TOKEN="), body.index('owner-token'))
        self.assertIn('{32,}', body)
        self.assertNotIn('Write-Host $token', body)

    def test_msi_removes_the_token_only_on_a_real_uninstall(self):
        root = ET.fromstring(WXS)
        self.assertTrue(root.tag.endswith('Wix'))
        self.assertIn('RemoveNeonHearthOwnerToken', WXS)
        match = re.search(r'<Custom Action="RemoveNeonHearthOwnerToken"[^>]*Condition="([^"]*)"', WXS)
        self.assertIsNotNone(match)
        condition = match.group(1).replace('&quot;', '"')
        self.assertIn('REMOVE="ALL"', condition)
        self.assertIn('NOT UPGRADINGPRODUCTCODE', condition)
        self.assertRegex(WXS, r'RemoveNeonHearthOwnerToken"\s+DllEntry="WixQuietExec64"[^>]*Return="ignore"')
        self.assertIn(r'[CommonAppDataFolder]NeonHearth\owner-token', WXS)

    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell required for the parser check')
    def test_scripts_parse(self):
        for name in ('configure-service.ps1', 'open-neonhearth.ps1'):
            path = WINDOWS / 'scripts' / name
            command = (
                "$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("
                f"'{path}',[ref]$t,[ref]$e);if($e.Count){{$e|ForEach-Object{{$_.Message}};exit 1}}"
            )
            result = subprocess.run(['pwsh', '-NoProfile', '-Command', command], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
