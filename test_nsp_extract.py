"""Synthetic round-trip checks for NSP extraction (no real games or keys)."""
from pathlib import Path
import hashlib
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import zstandard

sys.path.insert(0, str(Path(__file__).parent / 'src'))
import container_format as fmt
import nup_format
import nsp_extract as nx
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


TITLE = 0x0100abc123450000
HEADER_KEY = bytes((i * 7 + 3) & 0xff for i in range(32))
CONTENT_KEY = bytes((i * 11 + 5) & 0xff for i in range(16))


def xts_encrypt(key, buf, off, length, first_sector):
    """Inverse of nsp_extract.xts_decrypt, for building test fixtures only."""
    def enc(k, data):
        c = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
        return c.update(data) + c.finalize()
    for s in range(length // 0x200):
        tweak = bytearray(16)
        tweak[8:] = (first_sector + s).to_bytes(8, 'big')
        t = bytearray(enc(key[16:], bytes(tweak)))
        pos = off + s * 0x200
        for j in range(0, 0x200, 16):
            p = pos + j
            y = enc(key[:16], bytes(buf[p + k] ^ t[k] for k in range(16)))
            for k in range(16):
                buf[p + k] = y[k] ^ t[k]
            carry = 0
            for k in range(16):
                high = t[k] >> 7
                t[k] = ((t[k] << 1) | carry) & 0xff
                carry = high
            if carry:
                t[0] ^= 0x87
    return buf


def snapshot(root):
    exefs = root / 'exefs'; exefs.mkdir()
    (exefs / 'main').write_bytes(b'EXEFS-MAIN-CONTENT' * 8)
    npdm = bytearray(0x100)
    npdm[0:4] = b'META'
    struct.pack_into('<II', npdm, 0x70, 0x80, 0x30)
    npdm[0x80:0x84] = b'ACI0'
    struct.pack_into('<Q', npdm, 0x90, TITLE)
    (exefs / 'main.npdm').write_bytes(npdm)
    romfs = root / 'romfs'; (romfs / 'dir').mkdir(parents=True)
    (romfs / 'one.bin').write_bytes(bytes(range(256)) * 4)
    (romfs / 'dir' / 'two.bin').write_bytes(b'romfs-data' * 100)
    control = root / 'control'; control.mkdir()
    nacp = bytearray(0x4000)
    nacp[0:6] = b'MyGame'
    nacp[0x3060:0x3065] = b'1.0.0'
    (control / 'control.nacp').write_bytes(nacp)
    return exefs, romfs, control


def encrypted_nsp(root):
    """Build a synthetic retail-style NSP: XTS header, CTR sections, key-area key."""
    exefs, romfs, control = snapshot(root)
    program = fmt.nca([fmt.pfs_section(fmt.filesystem([(p.name, p) for p in sorted(exefs.iterdir())])),
                       fmt.romfs_section(fmt.romfs(romfs, []))], TITLE, 0)
    ctrl = fmt.nca([fmt.romfs_section(fmt.romfs(control, []))], TITLE, 2)
    entries = []
    for blob, ctype in ((program, 1), (ctrl, 3)):
        entries.append((blob.digest()[:16].hex() + '.nca', blob, ctype))

    prod = root / 'prod.keys'
    prod.write_text('header_key = ' + HEADER_KEY.hex() + '\n'
                    'key_area_key_application_00 = ' + CONTENT_KEY.hex() + '\n', encoding='utf-8')

    ncabs = []
    for name, blob, ctype in entries:
        raw = bytearray(b''.join(blob.chunks(1 << 20)))
        hdr = bytearray(raw[:0xc00])
        body = bytearray(raw[0xc00:])
        key_area = bytearray(0x40)
        key_area[0x20:0x30] = CONTENT_KEY
        c = Cipher(algorithms.AES(CONTENT_KEY), modes.ECB()).encryptor()
        hdr[0x300:0x340] = c.update(bytes(key_area)) + c.finalize()
        uppers = []
        for i in range(4):
            start = nx.u32(hdr, 0x240 + i * 16) * 0x200
            end = nx.u32(hdr, 0x244 + i * 16) * 0x200
            if start == end:
                continue
            fsh = 0x400 + i * 0x200
            hdr[fsh + 4] = 3  # AES-CTR
            upper = bytes((i * 17 + j) & 0xff for j in range(8))
            uppers.append((start, end, upper))
            hdr[fsh + 0x140:fsh + 0x148] = upper[::-1]
        for start, end, upper in uppers:
            for p in range(start, end, nx.CHUNK):
                piece = bytes(body[p - 0xc00:p - 0xc00 + min(nx.CHUNK, end - p)])
                body[p - 0xc00:p - 0xc00 + len(piece)] = nx.ctr_bytes(CONTENT_KEY, upper, p, piece)
        xts_encrypt(HEADER_KEY, hdr, 0, 0x400, 0)
        xts_encrypt(HEADER_KEY, hdr, 0x400, 0x800, 2)
        ncabs.append((name, bytes(hdr) + bytes(body)))

    nsp = root / 'encrypted.nsp'
    nsp.write_bytes(b''.join(fmt.package([(n, b) for n, b in ncabs]).chunks(1 << 20)))
    return nsp, exefs, romfs, prod


def nsz_from_nsp(nsp, prod, block=False):
    """Build a block-free NSZ from an encrypted NSP for round-trip tests."""
    keys = nx.Keys.load(prod)
    container = nx.Container(nsp)
    entries = []
    try:
        for nca in container.ncas(keys):
            head = bytearray(nca.source.read(0, 0x4000))
            records = bytearray()
            stream = bytearray()
            sections = [s for s in nca.sections if s.exists]
            for s in sections:
                plain = nca.open_section(s).read(0, s.size)
                records += struct.pack('<QQQQ', s.start, s.size, 3, 0)
                records += nca.content_key() + nca._upper(s) + bytes(8)
                stream += plain
            meta = b'NCZSECTN' + struct.pack('<Q', len(sections)) + bytes(records)
            if block:
                size = 1 << 14
                parts = [bytes(stream)[i:i + size] for i in range(0, len(stream), size)]
                packed = [zstandard.ZstdCompressor().compress(p) for p in parts]
                meta += (b'NCZBLOCK' + bytes([0, 0, 0, 14]) + struct.pack('<IQ', len(parts), len(stream))
                         + b''.join(struct.pack('<I', len(p)) for p in packed))
                payload = b''.join(packed)
            else:
                payload = zstandard.ZstdCompressor().compress(bytes(stream))
            ncz = bytes(head) + meta + payload
            entries.append((Path(nca.name).stem + '.ncz', ncz))
    finally:
        container.close()
    path = nsp.with_suffix('.nsz')
    path.write_bytes(b''.join(fmt.filesystem(entries).chunks(1 << 20)))
    return path


def plaintext_nsp(root):
    exefs, romfs, control = snapshot(root)
    program = fmt.nca([fmt.pfs_section(fmt.filesystem([(p.name, p) for p in sorted(exefs.iterdir())])),
                       fmt.romfs_section(fmt.romfs(romfs, []))], TITLE, 0)
    ctrl = fmt.nca([fmt.romfs_section(fmt.romfs(control, []))], TITLE, 2)
    entries = []
    for blob, ctype in ((program, 1), (ctrl, 3)):
        digest = blob.digest()
        entries.append((digest[:16].hex() + '.nca', blob))
    path = root / 'game.nsp'
    path.write_bytes(b''.join(fmt.package(entries).chunks(1 << 20)))
    return path, exefs, romfs


class BytesSource(nx.Source):
    def __init__(self, data):
        super().__init__(len(data))
        self.data = data

    def read(self, pos, size):
        return self.data[pos:pos + size]


class PatchTests(unittest.TestCase):
    def test_relocation_tree(self):
        node = bytearray(0x8000)  # offset table + one relocation bucket
        struct.pack_into('<I', node, 0x4004, 2)
        struct.pack_into('<QQI', node, 0x4010, 0, 0, 0)
        struct.pack_into('<QQI', node, 0x4024, 16, 0, 1)
        entries = nx.Nca._read_tree(BytesSource(bytes(node)), 0, len(node), 20, 2)
        self.assertEqual([nx.u64(e, 0) for e in entries], [0, 16])
        self.assertEqual([nx.u32(e, 16) for e in entries], [0, 1])

    def test_patched_source_selects_base_and_patch(self):
        patched = nx.PatchedSource([0, 16], [0, 0], [0, 1],
                                   BytesSource(b'A' * 16), BytesSource(b'B' * 16), 32)
        self.assertEqual(patched.read(0, 32), b'A' * 16 + b'B' * 16)
        self.assertEqual(patched.read(8, 16), b'A' * 8 + b'B' * 8)


class PlaintextTests(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp, exefs, romfs = plaintext_nsp(root)
            out = root / 'extracted'
            result = nx.extract(nsp, out)
            self.assertEqual(result['title_id'], f'{TITLE:016X}')
            game = out / result['title_id']
            for src in exefs.iterdir():
                self.assertEqual((game / 'exefs' / src.name).read_bytes(), src.read_bytes())
            for src in romfs.rglob('*'):
                if src.is_file():
                    rel = src.relative_to(romfs)
                    self.assertEqual((game / 'romfs' / rel).read_bytes(), src.read_bytes())
            self.assertEqual((game / 'control' / 'control.nacp').stat().st_size, 0x4000)
            self.assertIn('MyGame', (game / 'info.txt').read_text())

    def test_encrypted_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp, exefs, romfs, prod = encrypted_nsp(root)
            out = root / 'extracted'
            result = nx.extract(nsp, out, prod_keys=prod)
            self.assertEqual(result['title_id'], f'{TITLE:016X}')
            game = out / result['title_id']
            for src in exefs.iterdir():
                self.assertEqual((game / 'exefs' / src.name).read_bytes(), src.read_bytes())
            for src in romfs.rglob('*'):
                if src.is_file():
                    self.assertEqual((game / 'romfs' / src.relative_to(romfs)).read_bytes(), src.read_bytes())
            self.assertIn('MyGame', (game / 'info.txt').read_text())

    def test_cancel_stops_work_and_removes_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp, _, _ = plaintext_nsp(root)
            out = root / 'out'
            event = threading.Event()

            def notify(stage, value):
                if stage.startswith('Extracting files'):
                    event.set()

            with self.assertRaises(InterruptedError):
                nx.extract(nsp, out, notify=notify, cancel=event)
            self.assertFalse(out.exists())
            self.assertFalse(list(root.glob('.nsp-extract-*')))

    def test_encrypted_nsp_to_nup(self):
        import nup_tools
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp, _, _, prod = encrypted_nsp(root)
            out = root / 'game.nup'
            result = nx.nsp_to_nup(nsp, out, prod_keys=prod)
            self.assertEqual(Path(result['output']), out)
            self.assertTrue(out.is_file())
            with nup_format.Archive(out) as archive:
                self.assertTrue(archive.files)
                self.assertTrue(all(f[5] == 0 and f[1] == f[3] for f in archive.files))
            info = nup_tools.inspect(out)
            self.assertEqual(info['packages'], 1)
            self.assertEqual(info['packages_info'][0]['title_id'], f'{TITLE:016X}')
            nup_tools.extract(out, root / 'check')
            check = root / 'check' / 'base'
            self.assertEqual((check / 'exefs' / 'main').read_bytes(), b'EXEFS-MAIN-CONTENT' * 8)
            self.assertEqual((check / 'romfs' / 'dir' / 'two.bin').read_bytes(), b'romfs-data' * 100)
            self.assertFalse(list(root.glob('.nsp2nup-*')))

    def test_nsz_to_nsp_and_nup(self):
        import nup_tools
        import verify_format as vf
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp, exefs, romfs, prod = encrypted_nsp(root)
            nsz = nsz_from_nsp(nsp, prod)
            out_nsp = root / 'from-nsz.nsp'
            nx.nsp_to_nsp(nsz, out_nsp, prod_keys=prod)
            parts = vf.partition(out_nsp.read_bytes())
            program = next(v for v in parts.values() if len(v) >= 0xc00 and v[0x205] == 0)
            _, _, sections = vf.nca_sections(program)
            packed = vf.partition(next(b for k, b in sections if k == 'pfs'))
            self.assertEqual(bytes(packed['main']), (exefs / 'main').read_bytes())

            out_nup = root / 'from-nsz.nup'
            nx.nsp_to_nup(nsz, out_nup, prod_keys=prod)
            nup_tools.extract(out_nup, root / 'check')
            self.assertEqual((root / 'check' / 'base' / 'romfs' / 'dir' / 'two.bin').read_bytes(),
                             (romfs / 'dir' / 'two.bin').read_bytes())

    def test_ncz_spool_uses_output_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp, _, _, prod = encrypted_nsp(root)
            nsz = nsz_from_nsp(nsp, prod)
            seen = []
            real = tempfile.SpooledTemporaryFile

            def tracked(*args, **kwargs):
                seen.append(kwargs.get('dir'))
                return real(*args, **kwargs)

            with patch('nsp_extract.tempfile.SpooledTemporaryFile', side_effect=tracked):
                nx.nsp_to_nsp(nsz, root / 'spool.nsp', prod_keys=prod)
            self.assertIn(str(root), seen)

    def test_block_nsz_to_nsp(self):
        import verify_format as vf
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp, exefs, _, prod = encrypted_nsp(root)
            nsz = nsz_from_nsp(nsp, prod, block=True)
            out = root / 'blocked.nsp'
            nx.nsp_to_nsp(nsz, out, prod_keys=prod)
            parts = vf.partition(out.read_bytes())
            program = next(v for v in parts.values() if len(v) >= 0xc00 and v[0x205] == 0)
            _, _, sections = vf.nca_sections(program)
            packed = vf.partition(next(b for k, b in sections if k == 'pfs'))
            self.assertEqual(bytes(packed['main']), (exefs / 'main').read_bytes())

    def test_encrypted_nsp_to_nsp(self):
        import verify_format as vf
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp, exefs, romfs, prod = encrypted_nsp(root)
            out = root / 'game.nsp'
            result = nx.nsp_to_nsp(nsp, out, prod_keys=prod)
            self.assertEqual(Path(result['output']), out)
            parts = vf.partition(out.read_bytes())
            program = next(v for v in parts.values() if len(v) >= 0xc00 and v[0x205] == 0)
            _, _, sections = vf.nca_sections(program)
            packed_exefs = vf.partition(next(b for k, b in sections if k == 'pfs'))
            packed_romfs = vf.romfs_files(next(b for k, b in sections if k == 'romfs'))
            self.assertEqual(bytes(packed_exefs['main']), (exefs / 'main').read_bytes())
            self.assertEqual(bytes(packed_romfs['dir/two.bin']), (romfs / 'dir' / 'two.bin').read_bytes())
            self.assertFalse(list(root.glob('*.partial')))

    def test_cancel_before_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nsp, _, _ = plaintext_nsp(root)
            event = threading.Event()
            event.set()
            with self.assertRaises(InterruptedError):
                nx.extract(nsp, root / 'out', cancel=event)
            self.assertFalse((root / 'out').exists())

    def test_encrypted_header_rejects_missing_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = bytearray(root.joinpath('fake.nsp').read_bytes() if False else b'\0' * 0xc00)
            data[0x200:0x204] = b'XXXX'
            p = root / 'fake.nca'
            p.write_bytes(data)
            with self.assertRaises(nx.ExtractError):
                nx.extract(p, root / 'out')


if __name__ == '__main__':
    unittest.main()
