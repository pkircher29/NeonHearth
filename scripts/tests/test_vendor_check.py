import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('check_vendor', Path(__file__).resolve().parents[1] / 'check-vendor-sqlx.py')
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)

UPSTREAM_TOML = b'[package]\nname = "sqlx-sqlite"\n[dependencies.libsqlite3-sys]\nversion = "0.30.1"\n'
PATCHED_TOML = UPSTREAM_TOML.replace(b'0.30.1', b'0.39.1')


def base():
    upstream = {'Cargo.toml': UPSTREAM_TOML, 'Cargo.toml.orig': b'orig', 'src/lib.rs': b'fn main() {}\n'}
    vendored = {**upstream, 'Cargo.toml': PATCHED_TOML, 'NEONHEARTH-PATCH.md': b'note'}
    return upstream, vendored


class VendorCheckTests(unittest.TestCase):
    def test_documented_change_only_passes(self):
        self.assertEqual(check.compare(*base()), [])

    def test_modified_source_is_reported(self):
        upstream, vendored = base()
        vendored['src/lib.rs'] = b'fn main() { backdoor(); }\n'
        self.assertEqual(check.compare(upstream, vendored), ['modified: src/lib.rs'])

    def test_extra_or_missing_files_are_reported(self):
        upstream, vendored = base()
        vendored['build.rs'] = b'fn main(){}'
        del vendored['src/lib.rs']
        problems = check.compare(upstream, vendored)
        self.assertIn('not in upstream: build.rs', problems)
        self.assertIn('missing from vendor: src/lib.rs', problems)

    def test_any_other_manifest_change_is_reported(self):
        upstream, vendored = base()
        vendored['Cargo.toml'] = PATCHED_TOML + b'[dependencies.evil]\nversion = "1"\n'
        self.assertEqual(len(check.compare(upstream, vendored)), 1)

    def test_unpatched_manifest_is_reported(self):
        upstream, vendored = base()
        vendored['Cargo.toml'] = UPSTREAM_TOML
        self.assertEqual(len(check.compare(upstream, vendored)), 1)

    def test_the_real_vendor_directory_records_a_checksum(self):
        self.assertRegex(check.documented_checksum(), r'^[0-9a-f]{64}$')


if __name__ == '__main__':
    unittest.main()
