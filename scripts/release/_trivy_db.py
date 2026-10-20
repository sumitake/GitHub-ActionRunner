"""Bounded read-only lookup of public records in the pinned scanner's DB.

The bbolt v1.4.3 common Meta/Page/InBucket layouts define this little-endian
format. This reader opens no writer and follows only explicitly requested keys.
"""
# SPDX-License-Identifier: MPL-2.0
import hashlib
import mmap
import os
import pathlib
import stat
import struct


class DatabaseError(ValueError):
    pass


def require(condition):
    if not condition:
        raise DatabaseError('invalid bounded public database lookup')


class Reader:
    def __init__(self, path, expected_sha256):
        path = pathlib.Path(path)
        require(path.resolve(strict=True) == path)
        self.fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        self.data = None
        try:
            self.before = os.fstat(self.fd)
            require(stat.S_ISREG(self.before.st_mode) and self.before.st_nlink == 1 and 8192 <= self.before.st_size <= 2 * 2**30)
            self.data = mmap.mmap(self.fd, 0, access=mmap.ACCESS_READ)
            self.sha256 = hashlib.sha256(self.data).hexdigest()
            require(self.sha256 == expected_sha256)
            self.size, self.pages = len(self.data), 0
            size = self.unpack('<I', 24)[0]
            require(size in (4096, 8192, 16384, 32768, 65536))
            valid = []
            for page in (0, 1):
                offset = page * size
                pid, flags, count, overflow = self.unpack('<QHHI', offset)
                magic, version, candidate_size = self.unpack('<III', offset + 16)
                root = self.unpack('<Q', offset + 32)[0]
                highwater, txid, checksum = self.unpack('<QQQ', offset + 56)
                computed = 0xcbf29ce484222325
                for byte in self.data[offset + 16:offset + 72]:
                    computed = ((computed ^ byte) * 0x100000001b3) & (2**64 - 1)
                if (pid == page and flags == 4 and count == overflow == 0
                        and magic == 0xed0cdaed and version == 2 and candidate_size == size
                        and computed == checksum and 2 <= root < highwater
                        and highwater * size <= self.size):
                    valid.append((txid, root, highwater))
            require(bool(valid))
            self.txid, self.root, self.highwater = max(valid)
            self.page_size = size
        except BaseException:
            if self.data is not None:
                self.data.close()
            os.close(self.fd)
            raise

    def unpack(self, fmt, offset):
        require(0 <= offset <= len(self.data) - struct.calcsize(fmt))
        return struct.unpack_from(fmt, self.data, offset)

    def page(self, pgid):
        require(2 <= pgid < self.highwater)
        offset = pgid * self.page_size
        pid, flags, _count, overflow = self.unpack('<QHHI', offset)
        length = (overflow + 1) * self.page_size
        require(pid == pgid and flags in (1, 2) and length <= 16 * 2**20 and offset + length <= self.highwater * self.page_size)
        return bytes(self.data[offset:offset + length])

    def lookup(self, page, key):
        require(isinstance(key, bytes) and 0 < len(key) <= 4096)
        visited = set()
        for _depth in range(32):
            self.pages += 1
            require(self.pages <= 20000 and len(page) >= 16)
            pid, flags, count, _overflow = struct.unpack_from('<QHHI', page)
            require(flags in (1, 2) and 16 + count * 16 <= len(page) and pid not in visited)
            visited.add(pid)
            previous, selected, found = None, None, None
            for index in range(count):
                start = 16 + index * 16
                if flags == 1:
                    pos, ksize, child = struct.unpack_from('<IIQ', page, start)
                    vsize = 0
                else:
                    entry_flags, pos, ksize, vsize = struct.unpack_from('<IIII', page, start)
                    require(entry_flags in (0, 1))
                begin = start + pos
                require(begin >= 16 + count * 16 and 0 < ksize <= 2**20 and begin + ksize + vsize <= len(page))
                candidate = page[begin:begin + ksize]
                require(previous is None or previous < candidate)
                previous = candidate
                if flags == 1 and candidate <= key:
                    selected = child
                elif flags == 2 and candidate == key:
                    found = entry_flags, page[begin + ksize:begin + ksize + vsize]
            if flags == 2:
                return found
            if selected is None:
                return None
            page = self.page(selected)
        raise DatabaseError('public database depth budget')

    def bucket(self, page, key):
        result = self.lookup(page, key)
        if result is None:
            return None
        require(result[0] == 1 and len(result[1]) >= 16)
        root = struct.unpack_from('<Q', result[1])[0]
        return self.page(root) if root else result[1][16:]

    def value(self, buckets, key):
        page = self.page(self.root)
        for name in buckets:
            page = self.bucket(page, name)
            if page is None:
                return None
        value = self.lookup(page, key)
        if value is None:
            return None
        require(value[0] == 0 and len(value[1]) <= 2**20)
        return value[1]

    def close(self):
        try:
            require(hashlib.sha256(self.data).hexdigest() == self.sha256)
            after = os.fstat(self.fd)
            identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
            require(identity(self.before) == identity(after))
        finally:
            self.data.close()
            os.close(self.fd)
