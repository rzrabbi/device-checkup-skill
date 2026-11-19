"""Smoke tests: run the real read-only commands on this machine and check the JSON shape.

No downloads, no scans, no changes to the system. Baselines go to a temporary folder.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from helpers import SCAN_PY


def run(*args, env=None):
    p = subprocess.run([sys.executable, "-I", "-B", SCAN_PY] + list(args),
                       capture_output=True, text=True, timeout=600, env=env)
    if p.returncode != 0:
        raise AssertionError(f"exit {p.returncode}: {p.stderr[-2000:]}")
    return json.loads(p.stdout)


class TestSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.env = dict(os.environ, DEVICE_CHECKUP_DIR=cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_help(self):
        p = subprocess.run([sys.executable, "-I", "-B", SCAN_PY, "--help"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0)
        self.assertIn("persistence", p.stdout)

    def test_engines(self):
        d = run("engines", env=self.env)
        self.assertIn("clamav", d["engines"])
        self.assertIn("loki", d["engines"])

    def test_persistence(self):
        d = run("persistence", env=self.env)
        for key in ("total", "flagged", "entries", "not_checked"):
            self.assertIn(key, d)
        for e in d["entries"]:
            self.assertEqual(set(e), {"kind", "name", "command", "source", "system", "flagged", "reasons"})

    def test_posture(self):
        d = run("posture", env=self.env)
        self.assertTrue(d["checks"], "at least one posture check")
        for c in d["checks"]:
            self.assertIn(c["status"], {"ok", "warn", "bad", "unknown", "info"})

    def test_network(self):
        d = run("network", env=self.env)
        self.assertIsInstance(d["listeners"], list)

    def test_extensions(self):
        d = run("extensions", env=self.env)
        self.assertIsInstance(d["extensions"], list)

    def test_hash(self):
        p = os.path.join(self.tmp, "sample.txt")
        with open(p, "wb") as f:
            f.write(b"hello\n")
        d = run("hash", p, env=self.env)
        self.assertEqual(d["sha256"], "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03")

    def test_baseline_roundtrip(self):
        first = run("baseline", "diff", env=self.env)
        self.assertEqual(first.get("error"), "no baseline yet")
        saved = run("baseline", "save", "--note", "ci", env=self.env)
        self.assertTrue(os.path.isfile(saved["saved"]))
        d = run("baseline", "diff", env=self.env)
        self.assertIn("summary", d)
        listed = run("baseline", "list", env=self.env)
        self.assertGreaterEqual(listed["count"], 1)


if __name__ == "__main__":
    unittest.main()
