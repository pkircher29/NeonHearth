import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('ci_hashes', Path(__file__).resolve().parents[1] / 'ci-hashes.py')
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


class CiHashesTest(unittest.TestCase):
    def folder(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(root, ignore_errors=True))
        (root / 'x64').mkdir()
        (root / 'x64' / 'a.exe').write_bytes(b'alpha')
        (root / 'b.txt').write_bytes(b'beta')
        return root

    def test_round_trip_verifies(self):
        root = self.folder()
        value = ci.create(root)
        self.assertEqual(ci.verify(root, value), 2)

    def test_changed_file_is_detected(self):
        root = self.folder()
        value = ci.create(root)
        (root / 'x64' / 'a.exe').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'Hash mismatch'):
            ci.verify(root, value)

    def test_extra_and_missing_files_are_detected(self):
        root = self.folder()
        value = ci.create(root)
        (root / 'evil.dll').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError, 'Unlisted'):
            ci.verify(root, value)
        (root / 'evil.dll').unlink()
        (root / 'b.txt').unlink()
        with self.assertRaisesRegex(ValueError, 'Missing'):
            ci.verify(root, value)

    def test_rewritten_list_is_rejected_by_the_published_hash(self):
        root = self.folder()
        value = ci.create(root)
        (root / 'x64' / 'a.exe').write_bytes(b'tampered')
        ci.create(root)  # attacker regenerates the list inside the artifact
        with self.assertRaisesRegex(ValueError, 'published by the producing job'):
            ci.verify(root, value)

    def test_missing_expectation_fails_closed(self):
        root = self.folder()
        ci.create(root)
        for bad in ('', None, 'xyz'):
            with self.assertRaises(ValueError):
                ci.verify(root, bad)

    def test_cli_exit_codes(self):
        root = self.folder()
        self.assertEqual(ci.main(['verify', str(root), '--expect', '0' * 64]), 1)
        self.assertEqual(ci.main(['create', str(root)]), 0)


if __name__ == '__main__':
    unittest.main()
