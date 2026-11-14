import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('gate', Path(__file__).with_name('check-rust-imports.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def fixture(name=b'KERNEL32.dll'):
    image = bytearray(1024)
    image[:2] = b'MZ'
    struct.pack_into('<I', image, 60, 64)
    image[64:68] = b'PE\0\0'
    struct.pack_into('<HH', image, 68, 0x8664, 1)
    struct.pack_into('<HH', image, 84, 240, 2)
    struct.pack_into('<H', image, 88, 0x20b)
    struct.pack_into('<I', image, 148, 512)
    struct.pack_into('<I', image, 196, 16)
    struct.pack_into('<II', image, 208, 0x1000, 40)
    struct.pack_into('<IIII', image, 336, 512, 0x1000, 512, 512)
    struct.pack_into('<IIIII', image, 512, 0x1100, 0, 0, 0x1080, 0x1100)
    image[640:640 + len(name)] = name
    return image


class ImportGateTests(unittest.TestCase):
    def test_normal_import_and_empty_directory(self):
        self.assertEqual(gate.imports(fixture()), ['KERNEL32.dll'])
        image = fixture(); struct.pack_into('<I', image, 212, 512)
        self.assertEqual(gate.imports(image), ['KERNEL32.dll'])
        image = fixture(); struct.pack_into('<II', image, 208, 0, 0)
        self.assertEqual(gate.imports(image), [])

    def test_runtime_families_rejected_case_insensitively(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'owned.exe'
            for name in ['VCRUNTIME140.dll', 'vcruntime140_1.dll', 'MSVCP140.dll', 'CONCRT140.dll', 'MSVCR120.dll']:
                path.write_bytes(fixture(name.encode()))
                with self.assertRaisesRegex(gate.InvalidPE, 'external Visual C'):
                    gate.check(path)

    def test_all_truncated_prefixes_fail(self):
        image = fixture()
        for end in range(len(image)):
            with self.subTest(end=end), self.assertRaises(gate.InvalidPE):
                gate.imports(image[:end])

    def test_malformed_headers_and_rvas_fail_closed(self):
        mutations = [(60, '<I', 0xffffffff), (68, '<H', 0x14c), (70, '<H', 0),
                     (84, '<H', 65535), (88, '<H', 0x10b), (148, '<I', 8),
                     (196, '<I', 17), (208, '<I', 0x5000), (212, '<I', 19),
                     (212, '<I', 0xffffffff), (348, '<I', 0xfffffff0),
                     (524, '<I', 0x1200), (304, '<I', 0x1000)]
        for offset, fmt, value in mutations:
            image = fixture(); struct.pack_into(fmt, image, offset, value)
            with self.subTest(offset=offset), self.assertRaises(gate.InvalidPE):
                gate.imports(image)

    def test_unterminated_descriptor_and_dll_name_fail(self):
        image = fixture(); struct.pack_into('<I', image, 532, 1)
        with self.assertRaises(gate.InvalidPE): gate.imports(image)
        image = fixture(); image[640:] = b'x' * 384
        with self.assertRaises(gate.InvalidPE): gate.imports(image)

    def test_overlapping_sections_fail(self):
        image = fixture(); struct.pack_into('<H', image, 70, 2)
        struct.pack_into('<IIII', image, 376, 512, 0x1000, 512, 512)
        with self.assertRaises(gate.InvalidPE): gate.imports(image)


if __name__ == '__main__':
    unittest.main()
