"""Baseline snapshot and diff logic with fake collectors (runs on any OS)."""
import copy
import os
import shutil
import tempfile
import unittest
from unittest import mock

from helpers import scan


def item(kind, name, cmd, reasons=()):
    return scan.entry(kind, name, cmd, "test", list(reasons))


class TestBaseline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.persist = [item("registry-run", "Updater", r"C:\Program Files\A\up.exe"),
                        item("cron-user", "crontab", "0 * * * * /usr/bin/backup")]
        self.posture = [scan.chk("firewall", "Firewall", "ok", True)]
        self.listen = [{"proc": "sshd", "addr": "0.0.0.0", "port": 22, "pid": 1},
                       {"proc": "svchost", "addr": "::", "port": 49667, "pid": 2}]
        self.exts = [{"browser": "Chrome", "profile": "Default", "id": "x", "name": "Good",
                      "source": "store", "all_sites_access": False, "reasons": []}]
        self.patches = [
            mock.patch.dict(os.environ, {"DEVICE_CHECKUP_DIR": self.tmp}),
            mock.patch.object(scan, "collect_persistence", lambda: copy.deepcopy(self.persist)),
            mock.patch.object(scan, "collect_posture", lambda check_updates=False: copy.deepcopy(self.posture)),
            mock.patch.object(scan, "listeners", lambda: copy.deepcopy(self.listen)),
            mock.patch.object(scan, "collect_extensions", lambda include_builtin=False: (copy.deepcopy(self.exts), 0)),
            mock.patch.object(scan, "defender_status", lambda: None),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_changes(self):
        d = scan.diff_snapshots(scan.snapshot(), scan.snapshot())
        self.assertTrue(all(v in (0, None) for v in d["summary"].values()), d["summary"])

    def test_detects_changes(self):
        old = scan.snapshot()
        self.persist.append(item("registry-run", "Odd", r"C:\Users\b\AppData\Local\Temp\o.exe"))
        self.persist[1] = item("cron-user", "crontab", "*/5 * * * * /tmp/x")
        self.posture[0] = scan.chk("firewall", "Firewall", "bad", False)
        self.listen.append({"proc": "nc", "addr": "0.0.0.0", "port": 4444, "pid": 3})
        self.listen[1]["port"] = 49670  # dynamic port moved: not a change
        self.exts.append({"browser": "Edge", "profile": "Default", "id": "y", "name": "New",
                          "source": "force-installed by policy", "all_sites_access": True,
                          "reasons": ["policy"]})
        d = scan.diff_snapshots(old, scan.snapshot())
        s = d["summary"]
        self.assertEqual(s["startup_items_added"], 1)
        self.assertEqual(s["startup_items_changed"], 1)
        self.assertEqual(s["settings_changed"], 1)
        self.assertEqual(s["listening_ports_added"], 1)
        self.assertEqual(s["listening_ports_removed"], 0)
        self.assertEqual(s["browser_extensions_added"], 1)
        self.assertTrue(d["persistence"]["added"][0]["reasons"], "flagged additions first")
        self.assertEqual(d["posture"][0]["before"], "ok")

    def test_save_list_and_retention(self):
        for _ in range(3):
            scan.save_snapshot(scan.snapshot())
        self.assertGreaterEqual(len(scan.baseline_files()), 1)
        with mock.patch.object(scan, "BASELINE_KEEP", 1):
            scan.save_snapshot(scan.snapshot())
        self.assertEqual(len(scan.baseline_files()), 1)

    def test_old_baseline_without_extensions(self):
        old = scan.snapshot()
        del old["extensions"]
        d = scan.diff_snapshots(old, scan.snapshot())
        self.assertIsInstance(d["extensions"], str)
        self.assertIsNone(d["summary"]["browser_extensions_added"])


if __name__ == "__main__":
    unittest.main()
