"""Safe extraction and checksum verification for downloaded tools (no network)."""
import hashlib
import io
import os
import shutil
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock

from helpers import scan


class TestSafeExtract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.out = os.path.join(self.tmp, "out")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_zip_traversal_blocked(self):
        p = os.path.join(self.tmp, "a.zip")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("../escape.txt", "x")
        with self.assertRaises(ValueError):
            scan.safe_extract(p, self.out)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "escape.txt")))

    def test_zip_ok_and_pdb_skipped(self):
        p = os.path.join(self.tmp, "a.zip")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("tool/clamscan.exe", "bin")
            z.writestr("tool/clamscan.pdb", "debug")
        scan.safe_extract(p, self.out)
        self.assertTrue(os.path.isfile(os.path.join(self.out, "tool", "clamscan.exe")))
        self.assertFalse(os.path.exists(os.path.join(self.out, "tool", "clamscan.pdb")))

    def make_tar(self, add):
        p = os.path.join(self.tmp, "a.tar.gz")
        with tarfile.open(p, "w:gz") as t:
            add(t)
        return p

    def test_tar_traversal_blocked(self):
        def add(t):
            ti = tarfile.TarInfo("../escape.txt")
            ti.size = 1
            t.addfile(ti, io.BytesIO(b"x"))
        with self.assertRaises(ValueError):
            scan.safe_extract_tar(self.make_tar(add), self.out)

    def test_tar_symlink_outside_blocked(self):
        def add(t):
            ti = tarfile.TarInfo("link")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/etc/passwd"
            t.addfile(ti)
        with self.assertRaises(ValueError):
            scan.safe_extract_tar(self.make_tar(add), self.out)

    def test_tar_ok(self):
        def add(t):
            ti = tarfile.TarInfo("loki/loki")
            ti.size = 3
            t.addfile(ti, io.BytesIO(b"bin"))
        scan.safe_extract_tar(self.make_tar(add), self.out)
        self.assertTrue(os.path.isfile(os.path.join(self.out, "loki", "loki")))


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class TestDownloadVerified(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.data = b"pretend this is a release archive"
        self.dest = os.path.join(self.tmp, "file.bin")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fetch(self, digest):
        with mock.patch.object(scan, "http_get", lambda url, timeout=60: FakeResponse(self.data)):
            scan.download_verified("https://example.invalid/f", self.dest, digest)

    def test_good_checksum(self):
        self.fetch(hashlib.sha256(self.data).hexdigest())
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), self.data)

    def test_bad_checksum_discarded(self):
        with self.assertRaises(ValueError):
            self.fetch("0" * 64)
        self.assertFalse(os.path.exists(self.dest))
        self.assertFalse(os.path.exists(self.dest + ".part"))


if __name__ == "__main__":
    unittest.main()
