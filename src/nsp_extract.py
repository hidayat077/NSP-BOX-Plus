"""Extract encrypted retail NSP/XCI dumps into the folder layout NSP Box accepts.

Needs your own prod.keys (and title.keys or the NSP's tickets). Plaintext NSPs
need no keys. This is a Python port of the NCA/PFS0/RomFS/BKTR reader logic; it
does not include Nintendo code, keys or content.
"""
# shortcut: retail NSP/NSZ/XCI, common tickets, BKTR updates and DLC only; XCZ,
# NCA0, AES-XTS sections, sparse/compressed NCAs and personalised tickets are not
# handled. Non-block NCZ is decompressed into a spooled temp file once per read
# pass; block NCZ (the common form) is decompressed per block without a temp file.
from pathlib import Path
import json
import shutil
import struct
import sys
import tempfile

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as exc:  # pragma: no cover - dependency guard
    raise ImportError('NSP extraction requires the cryptography package.') from exc

CHUNK = 1 << 20
NCA_MAGICS = (b'NCA3', b'NCA2')

# Non-block NCZ needs one sequential decompression into a spool. Keep that
# spool on the output disk: /tmp is often a small-quota tmpfs.
_SPOOL_DIR = None


class ExtractError(Exception):
    pass


def check_cancel(cancel):
    if cancel is not None and cancel.is_set():
        raise InterruptedError('Extraction cancelled')


# --------------------------------------------------------------------------- helpers

def u8(buf, off):
    return buf[off]


def u32(buf, off):
    return struct.unpack_from('<I', buf, off)[0]


def u64(buf, off):
    return struct.unpack_from('<Q', buf, off)[0]


def be32(buf, off):
    return struct.unpack_from('>I', buf, off)[0]


def be64(buf, off):
    return struct.unpack_from('>Q', buf, off)[0]


def cstr(buf, off, limit):
    if off < 0 or off >= len(buf):
        return ''
    return bytes(buf[off:off + limit]).split(b'\0', 1)[0].decode('utf-8', 'replace')


def safe_name(name):
    """Reject traversal and reserved names before joining anything to the output root."""
    if not name or name in ('.', '..'):
        raise ExtractError('Unsafe path in archive: ' + repr(name))
    parts = name.replace('\\', '/').split('/')
    bad = {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'}
    bad.update('COM' + str(i) for i in range(1, 10))
    bad.update('LPT' + str(i) for i in range(1, 10))
    for p in parts:
        if not p or p in ('.', '..') or p != p.strip() or any(c in p for c in '<>:"|?*\x00'):
            raise ExtractError('Unsafe path in archive: ' + repr(name))
        if p.split('.')[0].upper() in bad:
            raise ExtractError('Unsafe path in archive: ' + repr(name))
    return '/'.join(parts)


# --------------------------------------------------------------------------- AES

def ecb_decrypt(key, data):
    if len(data) % 16:
        raise ExtractError('AES-ECB input is not block aligned')
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return d.update(data) + d.finalize()


def ecb_encrypt(key, data):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(data) + e.finalize()


def xts_decrypt(key, buf, off, length, first_sector):
    """In-place AES-128-XTS, 0x200 sectors, Nintendo big-endian reversed tweak."""
    if len(key) != 32:
        raise ExtractError('XTS needs a 32-byte key')
    # ECB contexts can be reused across blocks; update() emits one block at a
    # time, so no finalize() is needed. Rebuilding a cipher per 16 bytes was
    # the main cost of opening a container with many NCAs.
    enc = Cipher(algorithms.AES(key[16:]), modes.ECB()).encryptor()
    dec = Cipher(algorithms.AES(key[:16]), modes.ECB()).decryptor()
    tweak = bytearray(16)
    for s in range(length // 0x200):
        tweak[:] = bytes(16)
        tweak[8:] = (first_sector + s).to_bytes(8, 'big')
        t = bytearray(enc.update(bytes(tweak)))
        pos = off + s * 0x200
        for j in range(0, 0x200, 16):
            p = pos + j
            x = bytes(buf[p + k] ^ t[k] for k in range(16))
            y = dec.update(x)
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


def ctr_bytes(key, upper, absolute, data):
    """AES-CTR decrypt; upper is the 8-byte fixed half, absolute the NCA offset."""
    iv = bytes(upper) + ((absolute >> 4) & 0xffffffffffffffff).to_bytes(8, 'big')
    d = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return d.update(data) + d.finalize()


# --------------------------------------------------------------------------- sources

class Source:
    def __init__(self, size):
        self.size = size

    def read(self, pos, size):
        raise NotImplementedError

    def slice(self, off, size):
        if off < 0 or size < 0 or off + size > self.size:
            raise ExtractError('Read outside source bounds')
        return Slice(self, off, size)


class FileSource(Source):
    def __init__(self, path, offset, size):
        super().__init__(size)
        self.file = open(path, 'rb')
        self.offset = offset

    def read(self, pos, size):
        if pos < 0 or size < 0 or pos + size > self.size:
            raise ExtractError('Read past end of file')
        self.file.seek(self.offset + pos)
        data = self.file.read(size)
        if len(data) != size:
            raise ExtractError('Short read from ' + self.file.name)
        return data

    def close(self):
        self.file.close()


class Slice(Source):
    def __init__(self, base, off, size):
        super().__init__(size)
        self.base, self.off = base, off

    def read(self, pos, size):
        return self.base.read(self.off + pos, size)


class CtrSource(Source):
    def __init__(self, raw, key, upper, abs_start):
        super().__init__(raw.size)
        self.raw, self.key, self.upper, self.abs_start = raw, key, upper, abs_start

    def read(self, pos, size):
        if pos < 0 or size < 0 or pos + size > self.size:
            raise ExtractError('Read past end of section')
        out = bytearray()
        while size:
            absolute = self.abs_start + pos
            pre = absolute & 15
            take = min(size, CHUNK - pre)
            tmp = self.raw.read(pos - pre, pre + take)
            out += ctr_bytes(self.key, self.upper, absolute - pre, tmp)[pre:]
            pos += take
            size -= take
        return bytes(out)


class CtrExSource(Source):
    """Patch data: the counter's upper word comes from the BKTR subsection table."""
    def __init__(self, raw, key, upper, abs_start, offs, ctrs):
        super().__init__(raw.size)
        self.raw, self.key, self.upper = raw, key, upper
        self.abs_start, self.offs, self.ctrs = abs_start, offs, ctrs

    def read(self, pos, size):
        if pos < 0 or size < 0 or pos + size > self.size:
            raise ExtractError('Read past end of patch data')
        out = bytearray()
        while size:
            i = floor_index(self.offs, pos)
            end = self.offs[i + 1] if i + 1 < len(self.offs) else self.size
            n = min(size, end - pos)
            if n <= 0:
                raise ExtractError('Corrupt BKTR subsection table')
            upper = bytearray(self.upper)
            upper[4:8] = self.ctrs[i].to_bytes(4, 'big')
            out += CtrSource(self.raw, self.key, bytes(upper), self.abs_start).read(pos, n)
            pos += n
            size -= n
        return bytes(out)


class PatchedSource(Source):
    def __init__(self, virt, phys, storages, base, patch, total):
        super().__init__(total)
        self.virt, self.phys, self.storages = virt, phys, storages
        self.base, self.patch = base, patch

    def read(self, pos, size):
        out = bytearray()
        while size:
            i = floor_index(self.virt, pos)
            end = self.virt[i + 1] if i + 1 < len(self.virt) else self.size
            n = min(size, end - pos)
            p = self.phys[i] + (pos - self.virt[i])
            src = self.base if self.storages[i] == 0 else self.patch
            out += src.read(p, n)
            pos += n
            size -= n
        return bytes(out)


def floor_index(values, v):
    lo, hi = 0, len(values) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if values[mid] <= v:
            lo = mid
        else:
            hi = mid - 1
    return lo


# --------------------------------------------------------------------------- keys

class Keys:
    def __init__(self):
        self.values = {}
        self.title_keys = {}

    @classmethod
    def load(cls, prod=None, title=None):
        keys = cls()
        for path, is_title in ((prod, False), (title, True)):
            if not path:
                continue
            path = Path(path)
            if not path.is_file():
                raise ExtractError('Key file not found: ' + str(path))
            keys.parse(path.read_text(encoding='utf-8', errors='replace'), is_title)
        return keys

    def parse(self, text, title=False):
        for line in text.splitlines():
            line = line.strip()
            if not line or line[0] in ';#':
                continue
            if '=' not in line:
                continue
            name, value = line.split('=', 1)
            name = name.strip().lower()
            value = value.split()[0] if value.split() else ''
            if len(value) % 2:
                continue
            try:
                raw = bytes.fromhex(value)
            except ValueError:
                continue
            if title:
                if len(name) == 32:
                    self.title_keys[name] = raw
            else:
                self.values[name] = raw

    def get(self, name, length=None):
        value = self.values.get(name)
        if value is None or (length is not None and len(value) != length):
            return None
        return value

    def header_key(self):
        key = self.get('header_key', 32)
        if key is None:
            raise ExtractError('header_key is missing from prod.keys')
        return key

    def _derive(self, master, source):
        return ecb_decrypt(master, source)

    def key_area_key(self, index, gen):
        kinds = ('application', 'ocean', 'system')
        if not 0 <= index < len(kinds):
            raise ExtractError('Unknown key area index ' + str(index))
        kind = kinds[index]
        name = f'key_area_key_{kind}_{gen:02x}'
        direct = self.get(name, 16)
        if direct:
            return direct
        keygen = self.get(f'keygen_{gen:02x}')
        if keygen and len(keygen) >= 16:
            return keygen[:16]
        master = self.get(f'master_key_{gen:02x}', 16)
        kek_seed = self.get('aes_kek_generation_source', 16)
        key_seed = self.get('aes_key_generation_source', 16)
        source = self.get(f'key_area_key_{kind}_source', 16)
        if not (master and kek_seed and key_seed and source):
            raise ExtractError(f'Missing {name}: this game needs a newer prod.keys (master key {gen:02x})')
        return self._derive(self._derive(self._derive(master, kek_seed), source), key_seed)

    def titlekek(self, gen):
        name = f'titlekek_{gen:02x}'
        direct = self.get(name, 16)
        if direct:
            return direct
        master = self.get(f'master_key_{gen:02x}', 16)
        source = self.get('titlekek_source', 16)
        if not (master and source):
            raise ExtractError(f'Missing {name}: this game needs a newer prod.keys (master key {gen:02x})')
        return self._derive(master, source)

    def title_key(self, rights_hex):
        return self.title_keys.get(rights_hex.lower())

    def add_title_key(self, rights_hex, encrypted):
        self.title_keys[rights_hex.lower()] = encrypted


# --------------------------------------------------------------------------- PFS / RomFS listing

def pfs_entries(source):
    head = source.read(0, 16)
    if head[:4] not in (b'PFS0', b'HFS0'):
        raise ExtractError('Not a PFS0/HFS0 partition')
    hfs = head[:4] == b'HFS0'
    count, str_size = u32(head, 4), u32(head, 8)
    if count > 200000 or str_size > (1 << 24):
        raise ExtractError('Corrupt partition header')
    es = 0x40 if hfs else 0x18
    table = source.read(16, count * es + str_size)
    data_start = 16 + count * es + str_size
    out = []
    for i in range(count):
        off = i * es
        rel, size = u64(table, off), u64(table, off + 8)
        name_off = u32(table, off + 16)
        if name_off >= str_size:
            raise ExtractError('Corrupt partition string table')
        out.append((cstr(table, count * es + name_off, str_size - name_off), data_start + rel, size))
    return out


def romfs_entries(image):
    head = image.read(0, 0x50)
    if u64(head, 0) != 0x50:
        raise ExtractError('Not a RomFS image (bad header)')
    dir_off, dir_size = u64(head, 0x18), u64(head, 0x20)
    file_off, file_size, data_off = u64(head, 0x38), u64(head, 0x40), u64(head, 0x48)
    if dir_size > (256 << 20) or file_size > (512 << 20):
        raise ExtractError('Corrupt RomFS tables')
    dirs = image.read(dir_off, dir_size)
    files = image.read(file_off, file_size)
    out = []

    def walk(d, prefix, depth):
        if depth > 256:
            raise ExtractError('RomFS nesting too deep')
        try:
            f = u32(dirs, d + 12)
            while f != 0xffffffff:
                nlen = u32(files, f + 28)
                out.append((prefix + cstr(files, f + 32, nlen), data_off + u64(files, f + 8), u64(files, f + 16)))
                f = u32(files, f + 4)
            child = u32(dirs, d + 8)
            while child != 0xffffffff:
                nlen = u32(dirs, child + 20)
                walk(child, prefix + cstr(dirs, child + 24, nlen) + '/', depth + 1)
                child = u32(dirs, child + 4)
        except (IndexError, struct.error) as exc:
            raise ExtractError('Corrupt RomFS directory tree') from exc

    walk(0, '', 0)
    return out


# --------------------------------------------------------------------------- NCZ

class _NczSection:
    def __init__(self, offset, size, crypto_type, key, counter, stream):
        self.offset, self.size, self.crypto_type = offset, size, crypto_type
        self.key, self.counter, self.stream = key, counter, stream


class NczSource(Source):
    """Random-access view of a decompressed NCZ, re-encrypted as the original NCA."""
    def __init__(self, source, cancel=None):
        import zstandard

        self.source = source
        self.cancel = cancel
        check_cancel(cancel)
        if source.size < 0x4000 + 24:
            raise ExtractError('NCZ file is too small')
        marker = source.read(0x4000, 24)
        check_cancel(cancel)
        if marker[:8] != b'NCZSECTN':
            raise ExtractError('Not a supported NCZ file')
        count = u64(marker, 8)
        if not 0 < count <= 4096:
            raise ExtractError('Corrupt NCZ section count')
        table = source.read(0x4010, count * 64 + 16)
        check_cancel(cancel)
        sections = []
        stream_size = 0
        for i in range(count):
            check_cancel(cancel)
            at = i * 64
            sec = _NczSection(u64(table, at), u64(table, at + 8), u64(table, at + 16),
                              bytes(table[at + 32:at + 48]), bytes(table[at + 48:at + 64]), stream_size)
            if sec.size <= 0 or sec.offset + sec.size > (1 << 63):
                raise ExtractError('Corrupt NCZ section')
            sections.append(sec)
            stream_size += sec.size
        self.sections = sections
        self.stream_size = stream_size
        self.size = max(s.offset + s.size for s in sections)
        pos = 0x4010 + count * 64
        magic = source.read(pos, 8)
        self._zstd = zstandard.ZstdDecompressor()
        self._spool = None
        self._cache = (-1, b'')
        if magic == b'NCZBLOCK':
            head = source.read(pos, 24)
            exponent = head[11]
            blocks = u32(head, 12)
            if not 14 <= exponent <= 32 or not 0 < blocks <= (1 << 20):
                raise ExtractError('Corrupt NCZBLOCK header')
            sizes = []
            for i in range(blocks):
                check_cancel(cancel)
                sizes.append(u32(source.read(pos + 24 + 4 * i, 4), 0))
            check_cancel(cancel)
            self.block_size = 1 << exponent
            self.block_sizes = sizes
            self.block_start = pos + 24 + 4 * blocks
            # Cumulative packed offsets; summing the size list on every block
            # read made large NSZ conversions quadratic and felt like a hang.
            self._block_offsets = []
            running = self.block_start
            for size in sizes:
                self._block_offsets.append(running)
                running += size
        else:
            self.block_sizes = None
            self.stream_start = pos

    def _block(self, index):
        check_cancel(self.cancel)
        if index < 0 or index >= len(self.block_sizes):
            raise ExtractError('NCZ block index out of range')
        cached_index, cached = self._cache
        if cached_index == index:
            return cached
        offset = self._block_offsets[index]
        packed = self.source.read(offset, self.block_sizes[index])
        check_cancel(self.cancel)
        expected = min(self.block_size, self.stream_size - index * self.block_size)
        plain = packed if len(packed) >= expected else self._zstd.decompress(packed)
        check_cancel(self.cancel)
        if len(plain) != expected:
            raise ExtractError('NCZ block decompressed to an unexpected size')
        self._cache = (index, plain)
        return plain

    def _spooled(self):
        if self._spool is None:
            import tempfile
            spool = tempfile.SpooledTemporaryFile(max_size=64 * 1024 * 1024, dir=_SPOOL_DIR)
            try:
                dec = self._zstd.decompressobj()
                done = 0
                remaining = self.source.size - self.stream_start
                while remaining:
                    check_cancel(self.cancel)
                    n = min(4 * 1024 * 1024, remaining)
                    out = dec.decompress(self.source.read(self.stream_start + done, n))
                    if out:
                        spool.write(out)
                    done += n
                    remaining -= n
                check_cancel(self.cancel)
                tail = dec.flush()
                if tail:
                    spool.write(tail)
                spool.flush()
                self._spool = spool
            except BaseException:
                spool.close()
                raise
        return self._spool

    def _stream(self, pos, size):
        out = bytearray()
        while size:
            check_cancel(self.cancel)
            if self.block_sizes is None:
                spool = self._spooled()
                spool.seek(pos)
                chunk = spool.read(size)
                if not chunk:
                    break
                out += chunk
                pos += len(chunk)
                size -= len(chunk)
            else:
                index = pos // self.block_size
                if index >= len(self.block_sizes):
                    break
                block = self._block(index)
                at = pos % self.block_size
                take = min(size, len(block) - at)
                if take <= 0:
                    break
                out += block[at:at + take]
                pos += take
                size -= take
        return bytes(out)

    def read(self, pos, size):
        check_cancel(self.cancel)
        if pos < 0 or size < 0 or pos + size > self.size:
            raise ExtractError('Read past end of NCZ image')
        out = bytearray()
        if pos < 0x4000:
            n = min(size, 0x4000 - pos)
            out += self.source.read(pos, n)
            pos += n
            size -= n
        for sec in self.sections:
            check_cancel(self.cancel)
            lo = max(pos, sec.offset)
            hi = min(pos + size, sec.offset + sec.size)
            if lo >= hi:
                continue
            plain = self._stream(sec.stream + lo - sec.offset, hi - lo)
            if sec.crypto_type in (3, 4):
                plain = ctr_bytes(sec.key, sec.counter[:8], lo, plain)
            out += plain
        return bytes(out)


# --------------------------------------------------------------------------- container

class Container:
    def __init__(self, path):
        self.path = Path(path)
        self.source = FileSource(self.path, 0, self.path.stat().st_size)
        self.items = []
        self._ncz = []
        self._detect()

    def _detect(self):
        head = self.source.read(0, min(0x200, self.source.size))
        if head[:4] in (b'PFS0', b'HFS0'):
            for name, off, size in pfs_entries(self.source):
                self.items.append((name, off, size))
        elif head[0x100:0x104] == b'HEAD':
            self._xci()
        elif self.path.suffix.lower() in ('.nca', '.ncz'):
            self.items.append((self.path.name, 0, self.source.size))
        else:
            raise ExtractError('Unsupported file: expected NSP, XCI or NCA')

    def _xci(self):
        root = None
        for cand in (0x130, 0x138):
            off = u64(self.source.read(cand, 8), 0)
            if 0 < off + 4 <= self.source.size and self.source.read(off, 4) == b'HFS0':
                root = off
                break
        if root is None:
            root = 0xf000
        root_source = self.source.slice(root, self.source.size - root)
        for name, off, size in pfs_entries(root_source):
            if name != 'secure':
                continue
            base = root + off
            for child, c_off, c_size in pfs_entries(self.source.slice(base, size)):
                self.items.append((child, base + c_off, c_size))
        if not self.items:
            raise ExtractError('XCI has no secure partition content')

    def import_tickets(self, keys):
        for name, off, size in self.items:
            if not name.lower().endswith('.tik') or size < 0x2a0 + 16:
                continue
            try:
                t = self.source.read(off, min(size, 0x2c0))
                sig = u32(t, 0)
                if sig in (0x10000, 0x10003):
                    body = 4 + 0x200 + 0x3c
                elif sig in (0x10001, 0x10004):
                    body = 4 + 0x100 + 0x3c
                elif sig in (0x10002, 0x10005):
                    body = 4 + 0x3c + 0x40
                else:
                    continue
                if body + 0x170 > len(t) or t[body + 0x141] != 0:
                    continue
                rights = t[body + 0x160:body + 0x170].hex()
                keys.add_title_key(rights, t[body + 0x40:body + 0x50])
            except (ExtractError, IndexError, struct.error):
                continue

    def ncas(self, keys, errors=None, cancel=None):
        out = []
        for name, off, size in self.items:
            lower = name.lower()
            if not (lower.endswith('.nca') or lower.endswith('.ncz')):
                continue
            check_cancel(cancel)
            try:
                raw = self.source.slice(off, size)
                if lower.endswith('.ncz'):
                    raw = NczSource(raw, cancel)
                    self._ncz.append(raw)
                out.append(Nca(raw, keys, name))
            except InterruptedError:
                raise
            except Exception as exc:  # bad keys or unsupported NCA: report, keep going
                if errors is not None:
                    errors.append(f'{name}: {exc}')
        return out

    def close(self):
        for view in self._ncz:
            if view._spool is not None:
                view._spool.close()
        self.source.close()


# --------------------------------------------------------------------------- NCA

class Section:
    def __init__(self, index, start, end, header):
        self.index = index
        self.start, self.end = start, end
        self.header = header
        self.fs_type = header[2]
        self.hash_type = header[3]
        self.enc_type = header[4]

    @property
    def exists(self):
        return self.end > self.start

    @property
    def size(self):
        return self.end - self.start


class Nca:
    PROGRAM, META, CONTROL, MANUAL, DATA, PUBLIC_DATA = range(6)
    ROMFS, PFS = 0, 1
    ENC_NONE, ENC_XTS, ENC_CTR, ENC_CTR_EX = 1, 2, 3, 4

    def __init__(self, source, keys, name):
        self.source, self.keys, self.name = source, keys, name
        if source.size < 0xc00:
            raise ExtractError(name + ': too small to be an NCA')
        head = bytearray(source.read(0, 0xc00))
        if bytes(head[0x200:0x204]) in NCA_MAGICS:
            pass  # plaintext NCA (e.g. an NSP Box repack): header is already clear
        else:
            hk = keys.header_key()
            xts_decrypt(hk, head, 0, 0x400, 0)
            if bytes(head[0x200:0x204]) == b'NCA3':
                xts_decrypt(hk, head, 0x400, 0x800, 2)
            elif bytes(head[0x200:0x204]) == b'NCA2':
                for i in range(4):
                    xts_decrypt(hk, head, 0x400 + i * 0x200, 0x200, 0)
            else:
                raise ExtractError(name + ': cannot decrypt NCA header (wrong header_key?)')
        self.content_type = u8(head, 0x205)
        self.kak_index = u8(head, 0x207)
        self.size = u64(head, 0x208)
        self.title_id = u64(head, 0x210)
        gen = max(u8(head, 0x206), u8(head, 0x220))
        self.keygen = gen - 1 if gen else 0
        self.rights_id = bytes(head[0x230:0x240])
        self.key_area = bytes(head[0x300:0x340])
        self.sections = []
        for i in range(4):
            start = u32(head, 0x240 + i * 16) * 0x200
            end = u32(head, 0x244 + i * 16) * 0x200
            self.sections.append(Section(i, start, end, bytes(head[0x400 + i * 0x200:0x600 + i * 0x200])))
        self._content_key = None

    def has_rights_id(self):
        return any(self.rights_id)

    @property
    def rights_hex(self):
        return self.rights_id.hex()

    def is_patch(self):
        s = self.section(self.ROMFS)
        return s is not None and s.enc_type == self.ENC_CTR_EX

    def section(self, fs_type):
        for s in self.sections:
            if s.exists and s.fs_type == fs_type:
                return s
        return None

    def content_key(self):
        if self._content_key is not None:
            return self._content_key
        if self.has_rights_id():
            enc = self.keys.title_key(self.rights_hex)
            if enc is None:
                raise ExtractError(self.name + ': no title key for rights id ' + self.rights_hex)
            self._content_key = ecb_decrypt(self.keys.titlekek(self.keygen), enc)
        else:
            area = ecb_decrypt(self.keys.key_area_key(self.kak_index, self.keygen), self.key_area)
            self._content_key = area[0x20:0x30]
        return self._content_key

    @staticmethod
    def _upper(section):
        return bytes(section.header[0x140 + 7 - i] for i in range(8))

    def open_section(self, section):
        if section is None or not section.exists:
            raise ExtractError(self.name + ': section missing')
        raw = self.source.slice(section.start, section.size)
        if section.enc_type == self.ENC_NONE:
            return raw
        if section.enc_type in (0, self.ENC_CTR):
            return CtrSource(raw, self.content_key(), self._upper(section), section.start)
        if section.enc_type == self.ENC_XTS:
            raise ExtractError(self.name + ': AES-XTS sections are not supported')
        raise ExtractError(self.name + ': unsupported section encryption ' + str(section.enc_type))

    def open_data(self, section):
        decrypted = self.open_section(section)
        h = section.header
        if section.hash_type in (2, 5):
            off, size = u64(h, 0x40), u64(h, 0x48)
        elif section.hash_type in (3, 6):
            off, size = u64(h, 0x90), u64(h, 0x98)
        else:
            raise ExtractError(self.name + ': unsupported hash layout ' + str(section.hash_type))
        if off < 0 or size <= 0 or off + size > section.size:
            raise ExtractError(self.name + ': corrupt section layout')
        return decrypted.slice(off, size)

    def open_patched_romfs(self, patch, base_section):
        h = patch.header
        rel_off, rel_size = u64(h, 0x100), u64(h, 0x108)
        if h[0x110:0x114] == b'BKTR':
            rel_count = u32(h, 0x118)
            sub_off, sub_size, sub_count = u64(h, 0x120), u64(h, 0x128), u32(h, 0x138)
        else:
            sub_off, sub_size = u64(h, 0x110), u64(h, 0x118)
            rel_count, sub_count = u32(h, 0x128), u32(h, 0x138)
        if rel_count <= 0 or sub_count <= 0:
            raise ExtractError(self.name + ': patch has no BKTR tables')
        raw = self.source.slice(patch.start, patch.size)
        key, upper = self.content_key(), self._upper(patch)
        plain = CtrSource(raw, key, upper, patch.start)
        rel = self._read_tree(plain, rel_off, rel_size, 20, rel_count)
        sub = self._read_tree(plain, sub_off, sub_size, 16, sub_count)
        sub_offs = [u64(e, 0) for e in sub]
        sub_ctrs = [u32(e, 12) for e in sub]
        patch_data = CtrExSource(raw, key, upper, patch.start, sub_offs, sub_ctrs)
        virt = [u64(e, 0) for e in rel]
        phys = [u64(e, 8) for e in rel]
        stor = [u32(e, 16) for e in rel]
        # Total virtual image size lives in the relocation table header, not
        # in the FS header (where offset 0x8 is the IVFC magic).
        virtual_size = u64(plain.read(rel_off, 16), 8) or ((1 << 63) - 1)
        patched = PatchedSource(virt, phys, stor, base_section, patch_data, virtual_size)
        return self._fs_data(patch, patched)

    def _fs_data(self, section, decrypted):
        h = section.header
        if section.hash_type in (2, 5):
            off, size = u64(h, 0x40), u64(h, 0x48)
        elif section.hash_type in (3, 6):
            off, size = u64(h, 0x90), u64(h, 0x98)
        else:
            raise ExtractError(self.name + ': unsupported hash layout ' + str(section.hash_type))
        return decrypted.slice(off, size)

    @staticmethod
    def _read_tree(source, off, size, entry_size, count):
        if size <= 0 or size > (64 << 20):
            raise ExtractError('Corrupt BKTR table')
        data = source.read(off, size)
        node = 0x4000
        offset_count = (node - 16) // 8
        per_set = (node - 16) // entry_size
        sets = (count + per_set - 1) // per_set
        storage = node if sets <= offset_count else ((sets + offset_count - 1) // offset_count + 1) * node
        out = []
        for si in range(sets):
            base = storage + si * node
            if base + 16 > len(data):
                raise ExtractError('Corrupt BKTR table')
            n = u32(data, base + 4)
            for k in range(n):
                pos = base + 16 + k * entry_size
                if pos + entry_size > len(data):
                    raise ExtractError('Corrupt BKTR table')
                out.append(data[pos:pos + entry_size])
                if len(out) == count:
                    return out
        raise ExtractError('BKTR entry count mismatch')


# --------------------------------------------------------------------------- extraction

def _app_id(title_id):
    return title_id & ~0xfff


def find_nca(ncas, predicate, label):
    found = sorted((n for n in ncas if predicate(n)), key=lambda n: n.title_id)
    if not found:
        raise ExtractError(label + ' not found')
    return found[0]


def build_jobs(base_c, update_c, dlc_containers, keys, exefs, romfs, control, dlc_romfs, errors, cancel=None):
    base_ncas = base_c.ncas(keys, errors, cancel) if base_c else []
    update_ncas = update_c.ncas(keys, errors, cancel) if update_c else []
    all_ncas = base_ncas + update_ncas
    jobs = []
    title_id = None

    if exefs or romfs or control:
        if not base_c:
            raise ExtractError('A base game NSP is required')
        base_prog = find_nca(base_ncas, lambda n: n.content_type == Nca.PROGRAM and not n.is_patch(), 'Base program NCA')
        title_id = base_prog.title_id
        upd_prog = None
        if update_c:
            try:
                upd_prog = find_nca(update_ncas, lambda n: n.content_type == Nca.PROGRAM and n.is_patch(), 'Update program NCA')
            except ExtractError:
                upd_prog = None

        if exefs:
            n = upd_prog or base_prog
            section = n.section(Nca.PFS)
            if section is None:
                raise ExtractError('ExeFS section not found')
            img = n.open_data(section)
            for name, off, size in pfs_entries(img):
                check_cancel(cancel)
                jobs.append((f'exefs/{safe_name(name)}', img, off, size))

        if romfs:
            base_rom = base_prog.section(Nca.ROMFS)
            upd_rom = upd_prog.section(Nca.ROMFS) if upd_prog else None
            if upd_rom is not None and upd_rom.enc_type == Nca.ENC_CTR_EX:
                if base_rom is None:
                    raise ExtractError('Base game has no RomFS to patch')
                img = upd_prog.open_patched_romfs(upd_rom, base_prog.open_section(base_rom))
            elif upd_rom is not None:
                img = upd_prog.open_data(upd_rom)
            elif base_rom is not None:
                img = base_prog.open_data(base_rom)
            else:
                raise ExtractError('RomFS section not found')
            for name, off, size in romfs_entries(img):
                check_cancel(cancel)
                jobs.append((f'romfs/{safe_name(name)}', img, off, size))

        if control:
            controls = [n for n in all_ncas if n.content_type == Nca.CONTROL]
            if controls:
                ctrl = controls[-1]
                section = ctrl.section(Nca.ROMFS) or ctrl.section(Nca.PFS)
                if section is not None:
                    img = ctrl.open_data(section)
                    listing = romfs_entries(img) if section.fs_type == Nca.ROMFS else pfs_entries(img)
                    for name, off, size in listing:
                        check_cancel(cancel)
                        jobs.append((f'control/{safe_name(name)}', img, off, size))

    dlc_all = []
    if dlc_romfs:
        for container in dlc_containers:
            check_cancel(cancel)
            container.import_tickets(keys)
            dlc_ncas = container.ncas(keys, errors, cancel)
            dlc_all.extend(dlc_ncas)
            for n in dlc_ncas:
                check_cancel(cancel)
                if n.content_type not in (Nca.DATA, Nca.PUBLIC_DATA):
                    continue
                section = n.section(Nca.ROMFS)
                if section is None:
                    continue
                img = n.open_data(section)
                prefix = f'dlc/{n.title_id:016X}/romfs/'
                for name, off, size in romfs_entries(img):
                    check_cancel(cancel)
                    jobs.append((prefix + safe_name(name), img, off, size))

    return title_id, jobs, all_ncas + dlc_all


def _read_nacp(root):
    path = root / 'control' / 'control.nacp'
    if not path.is_file():
        return '', ''
    data = path.read_bytes()[:0x4000]
    name, version = '', ''
    for i in range(16):
        value = data[i * 0x300:i * 0x300 + 0x200].split(b'\0', 1)[0].decode('utf-8', 'replace').strip()
        if value:
            name = value
            break
    version = data[0x3060:0x3070].split(b'\0', 1)[0].decode('utf-8', 'replace').strip()
    return name, version


def extract(path, output, prod_keys=None, title_keys=None, update=None, dlc=(),
            exefs=True, romfs=True, control=True, dlc_romfs=True,
            notify=lambda *a: None, cancel=None):
    """Extract an encrypted NSP (optionally with update + DLC) into a new folder.

    Returns a small result dict. The output is staged beside its final location
    and renamed only on success, so a cancelled run never leaves a partial game.
    """
    global _SPOOL_DIR
    output = Path(output).absolute()
    _SPOOL_DIR = str(output.parent)
    if output.exists():
        raise ExtractError('Choose a new output folder; existing files are never overwritten.')
    check_cancel(cancel)
    output.parent.mkdir(parents=True, exist_ok=True)
    notify('Loading keys', 0)
    keys = Keys.load(prod_keys, title_keys)
    stage = Path(tempfile.mkdtemp(prefix='.nsp-extract-', dir=output.parent))
    containers = []
    committed = False
    try:
        notify('Opening containers', 0)
        base_c = Container(path)
        containers.append(base_c)
        base_c.import_tickets(keys)
        update_c = Container(update) if update else None
        if update_c:
            containers.append(update_c)
            update_c.import_tickets(keys)
        dlc_containers = []
        for item in dlc:
            c = Container(item)
            containers.append(c)
            dlc_containers.append(c)

        notify('Reading NCA headers', 0)
        errors = []
        title_id, jobs, _ = build_jobs(base_c, update_c, dlc_containers, keys, exefs, romfs,
                                       control, dlc_romfs, errors, cancel)
        notify(f'Building file list · {len(jobs):,} files', 1)
        if not jobs:
            raise ExtractError('Nothing to extract' + ((' · ' + errors[0]) if errors else ''))
        if title_id is None:
            raise ExtractError('No program title ID found in the base game')

        game_root = stage / f'{title_id:016X}'
        game_root.mkdir(parents=True)
        total = sum(j[3] for j in jobs)
        done = 0
        notify('Extracting files', 1)
        for rel, source, off, size in jobs:
            check_cancel(cancel)
            dest = game_root / safe_name(rel)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open('wb') as out:
                pos = 0
                while pos < size:
                    check_cancel(cancel)
                    n = min(CHUNK, size - pos)
                    out.write(source.read(off + pos, n))
                    pos += n
                    done += n
                    notify(f'Extracting files · {rel}', 1 + 98 * done / max(total, 1))
        check_cancel(cancel)
        if control:
            name, version = _read_nacp(game_root)
            if version or name:
                (game_root / 'info.txt').write_text(
                    f'Title ID: {title_id:016X}\r\nName: {name}\r\nVersion: {version}\r\n',
                    encoding='utf-8')
        notify('Finalizing', 99)
        stage.rename(output)
        committed = True
        notify('Extraction complete', 100)
        return {'output': str(output), 'title_id': f'{title_id:016X}', 'files': len(jobs),
                'size': total, 'warnings': errors}
    finally:
        for c in containers:
            c.close()
        if not committed and stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


class _Reader:
    """Sequential, context-managed view over a decrypted NCA range."""
    def __init__(self, source, offset, size):
        self.source, self.offset, self.size, self.pos = source, offset, size, 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        n = min(n, self.size - self.pos)
        if n <= 0:
            return b''
        data = self.source.read(self.offset + self.pos, n)
        self.pos += len(data)
        return data


def _nca_version(nca):
    section = nca.section(Nca.PFS)
    if section is None:
        return 0
    image = nca.open_data(section)
    for name, off, size in pfs_entries(image):
        if name.lower().endswith('.cnmt'):
            return u32(image.read(off, min(size, 0x40)), 8)
    return 0


def build_nup_packages(title_id, jobs, ncas, cancel=None):
    """Turn extracted-file jobs into NUP packages without writing them to disk."""
    import nup_format
    import nup_tools

    files, dlc = {}, {}
    for rel, source, off, size in jobs:
        check_cancel(cancel)
        item = nup_format.Source(size, lambda s=source, o=off, n=size: _Reader(s, o, n))
        if rel.startswith('dlc/'):
            parts = rel.split('/')
            dlc.setdefault(int(parts[1], 16), {})['/'.join(parts[2:])] = item
        else:
            files[rel] = item
    versions = [_nca_version(n) for n in ncas if n.content_type == Nca.META]
    version = max(versions) if versions else 0
    packages = [nup_format.Package(title_id, version, 0, files,
                                   {'exefs', 'romfs', 'control'}, nup_tools.metadata_for(files))]
    for tid, dlc_files in dlc.items():
        packages.append(nup_format.Package(tid, version, 2, dlc_files,
                                           {'romfs'}, nup_tools.metadata_for(dlc_files)))
    return packages


def nsp_to_nup(path, output, prod_keys=None, title_keys=None, update=None, dlc=(),
               exefs=True, romfs=True, control=True, dlc_romfs=True,
               notify=lambda *a: None, cancel=None):
    """Decrypt a retail NSP straight into a NUP, using the existing folder packer.

    Files stream straight from the decrypted NCA views into the NUP packer: no
    intermediate folder is written. An update is merged into the base RomFS,
    so the result is a single current snapshot (not separate update packages).
    """
    import nup_format

    global _SPOOL_DIR
    output = Path(output).absolute()
    _SPOOL_DIR = str(output.parent)
    if output.suffix.lower() != '.nup':
        raise ExtractError('NUP output must end in .nup')
    if output.exists():
        raise ExtractError('Choose a new output file; existing files are never overwritten.')
    check_cancel(cancel)
    notify('Loading keys', 0)
    keys = Keys.load(prod_keys, title_keys)
    containers = []
    try:
        notify('Opening containers', 0)
        base_c = Container(path)
        containers.append(base_c)
        base_c.import_tickets(keys)
        update_c = Container(update) if update else None
        if update_c:
            containers.append(update_c)
            update_c.import_tickets(keys)
        dlc_containers = []
        for item in dlc:
            c = Container(item)
            containers.append(c)
            dlc_containers.append(c)

        notify('Reading NCA headers', 0)
        errors = []
        title_id, jobs, ncas = build_jobs(base_c, update_c, dlc_containers, keys, exefs,
                                          romfs, control, dlc_romfs, errors, cancel)
        if not jobs:
            raise ExtractError('Nothing to convert' + ((' · ' + errors[0]) if errors else ''))
        notify(f'Building packages · {len(jobs):,} files', 1)
        packages = build_nup_packages(title_id, jobs, ncas, cancel)

        def packing(stage, value):
            notify(stage, 2 + value * 0.98)

        # Raw payloads: level 0 keeps every file uncompressed in the NUP.
        result = nup_format.pack(packages, output, level=0, notify=packing, cancel=cancel)
        result['title_id'] = f'{title_id:016X}'
        return result
    finally:
        for c in containers:
            c.close()


def nsp_to_nsp(path, output, prod_keys=None, title_keys=None, update=None,
               notify=lambda *a: None, cancel=None):
    """Decrypt a retail NSP straight into a plaintext NSP Box .nsp.

    ExeFS, RomFS and control data stream from the decrypted NCA views into the
    writer; no extracted folder is created. DLC is out of scope here.
    """
    import hashlib
    import os
    import uuid
    import container_format as fmt

    global _SPOOL_DIR
    output = Path(output).absolute()
    _SPOOL_DIR = str(output.parent)
    if output.suffix.lower() != '.nsp':
        raise ExtractError('NSP output must end in .nsp')
    if output.exists():
        raise ExtractError('Choose a new output file; existing files are never overwritten.')
    check_cancel(cancel)
    notify('Loading keys', 0)
    keys = Keys.load(prod_keys, title_keys)
    containers = []
    try:
        notify('Opening containers', 0)
        base_c = Container(path)
        containers.append(base_c)
        base_c.import_tickets(keys)
        update_c = Container(update) if update else None
        if update_c:
            containers.append(update_c)
            update_c.import_tickets(keys)

        notify('Reading NCA headers', 0)
        errors = []
        title_id, jobs, ncas = build_jobs(base_c, update_c, (), keys, True, True, True,
                                          False, errors, cancel)
        if not jobs:
            raise ExtractError('Nothing to convert' + ((' · ' + errors[0]) if errors else ''))

        fmt.configure(cancel, lambda done, total: notify('Building NSP integrity trees',
                                                        2 + 40 * done / max(total, 1)))
        view = lambda j: fmt.View(j[1], j[2], j[3])
        exefs = sorted((j for j in jobs if j[0].startswith('exefs/')), key=lambda j: j[0])
        romfs = [j for j in jobs if j[0].startswith('romfs/')]
        control = [j for j in jobs if j[0].startswith('control/')]
        if not exefs or not romfs:
            raise ExtractError('A complete ExeFS and RomFS snapshot is required')

        notify('Building game section', 42)
        program = fmt.nca([fmt.pfs_section(fmt.filesystem([(j[0].split('/', 1)[1], view(j)) for j in exefs])),
                           fmt.romfs_section(fmt.romfs(None, [], entries=[(j[0][6:], j[3], view(j)) for j in romfs]))],
                          title_id, 0, 0)
        ctrl_image = fmt.romfs(None, [], entries=[(j[0][8:], j[3], view(j)) for j in control])
        control_nca = fmt.nca([fmt.romfs_section(ctrl_image)], title_id, 2, 0)

        versions = [_nca_version(n) for n in ncas if n.content_type == Nca.META]
        version = max(versions) if versions else 0
        entries = []
        records = []
        for blob, ctype in ((program, 1), (control_nca, 3)):
            digest = blob.digest()
            entries.append((digest[:16].hex() + '.nca', blob))
            records.append(digest + digest[:16] + blob.size.to_bytes(6, 'little') + bytes([ctype, 0]))
        cnmt = bytearray(0x20)
        struct.pack_into('<QIBBHHH', cnmt, 0, title_id, version, 0x80, 0, 16, len(records), 0)
        cnmt += fmt.pack('QII', title_id + 0x800, 0, 0) + b''.join(records) + fmt.sha(cnmt)
        meta = fmt.nca([fmt.pfs_section(fmt.filesystem([(f'Application_{title_id:016x}.cnmt', bytes(cnmt))]))],
                       title_id, 1, 0)
        entries.append((meta.digest()[:16].hex() + '.cnmt.nca', meta))
        image = fmt.package(entries)

        notify('Writing NSP', 45)
        output.parent.mkdir(parents=True, exist_ok=True)
        temp = output.parent / (output.name + '.' + uuid.uuid4().hex[:10] + '.partial')
        digest = hashlib.sha256()
        done = 0
        committed = False
        try:
            with temp.open('xb') as out:
                for block in image.chunks(4 * 1024 * 1024):
                    check_cancel(cancel)
                    out.write(block)
                    digest.update(block)
                    done += len(block)
                    notify('Writing NSP', 45 + 55 * done / max(image.size, 1))
                out.flush()
                os.fsync(out.fileno())
            temp.rename(output)
            committed = True
        finally:
            if not committed and temp.exists():
                temp.unlink()
        notify('NSP ready', 100)
        return {'output': str(output), 'title_id': f'{title_id:016X}', 'size': image.size,
                'sha256': digest.hexdigest(), 'warnings': errors}
    finally:
        for c in containers:
            c.close()


def default_keys():
    """Best-effort locations, mirroring NxExtractor's automatic key discovery."""
    candidates = [Path.home() / '.switch' / 'prod.keys', Path.cwd() / 'prod.keys']
    for p in candidates:
        if p.is_file():
            return p
    return None


def cli_main(argv):
    import argparse
    parser = argparse.ArgumentParser(description='Extract an encrypted NSP into an extracted game folder.')
    parser.add_argument('--input', type=Path, required=True, help='Base NSP/NSZ/XCI (or NCA/NCZ).')
    parser.add_argument('--output', type=Path, required=True, help='New output folder.')
    parser.add_argument('--update', type=Path, help='Optional update NSP to merge on top.')
    parser.add_argument('--dlc', type=Path, action='append', default=[], help='DLC NSP (repeatable).')
    parser.add_argument('--prod-keys', type=Path, default=default_keys())
    parser.add_argument('--title-keys', type=Path)
    parser.add_argument('--no-exefs', action='store_true')
    parser.add_argument('--no-romfs', action='store_true')
    parser.add_argument('--no-control', action='store_true')
    parser.add_argument('--no-dlc', action='store_true')
    parser.add_argument('--to-nup', action='store_true', help='Pack the decrypted snapshot into a .NUP instead of a folder.')
    parser.add_argument('--to-nsp', action='store_true', help='Build a plaintext NSP Box .nsp instead of a folder.')
    args = parser.parse_args(argv)
    options = dict(prod_keys=args.prod_keys, title_keys=args.title_keys, update=args.update, dlc=args.dlc,
                   exefs=not args.no_exefs, romfs=not args.no_romfs,
                   control=not args.no_control, dlc_romfs=not args.no_dlc)
    if args.to_nup and args.to_nsp:
        raise ValueError('Choose only one of --to-nup or --to-nsp.')
    if args.to_nup:
        options.pop('dlc', None)
        result = nsp_to_nup(args.input, args.output, **options)
    elif args.to_nsp:
        result = nsp_to_nsp(args.input, args.output, prod_keys=args.prod_keys,
                            title_keys=args.title_keys, update=args.update)
    else:
        result = extract(args.input, args.output, **options)
    if sys.stdout:
        print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(cli_main(sys.argv[1:]))
