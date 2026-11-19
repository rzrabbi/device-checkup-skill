"""Windows startup-location logic with a fake registry (runs on any OS)."""
import unittest
from unittest import mock

from helpers import scan

WL = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
IFEO = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
WIN = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"


def fake_registry(values, subkeys):
    def reg_get(hive, sub, name):
        return values.get((hive, sub, name))

    def reg_subkeys(hive, sub):
        return subkeys.get((hive, sub), [])

    return reg_get, reg_subkeys


class TestHijackPoints(unittest.TestCase):
    def run_with(self, values, subkeys=None):
        get, subs = fake_registry(values, subkeys or {})
        with mock.patch.object(scan, "reg_get", get), \
                mock.patch.object(scan, "reg_subkeys", subs), \
                mock.patch.object(scan, "WINDIR", r"c:\windows"):
            return {(i["kind"], i["name"]): i for i in scan.win_hijack_points()}

    def test_normal_system_is_quiet(self):
        items = self.run_with({
            ("HKLM", WL, "Shell"): "explorer.exe",
            ("HKLM", WL, "Userinit"): r"C:\Windows\system32\userinit.exe,",
        }, {("HKLM", IFEO): ["notepad.exe"]})
        self.assertFalse(any(i["flagged"] for i in items.values()))
        self.assertTrue(items[("winlogon", "Shell")]["system"])

    def test_hijacks_are_flagged(self):
        items = self.run_with({
            ("HKLM", WL, "Shell"): "explorer.exe, other.exe",
            ("HKLM", WL, "Userinit"): r"C:\Windows\system32\userinit.exe, C:\x\run.exe",
            ("HKCU", WL, "Shell"): "other.exe",
            ("HKLM", IFEO + r"\sethc.exe", "Debugger"): "cmd.exe",
            ("HKLM", WIN, "AppInit_DLLs"): r"C:\x\hook.dll",
            ("HKLM", WIN, "LoadAppInit_DLLs"): 1,
        }, {("HKLM", IFEO): ["sethc.exe", "notepad.exe"]})
        for key in [("winlogon", "Shell"), ("winlogon", "Userinit"),
                    ("winlogon", "Shell (current user)"), ("debugger-hijack", "sethc.exe"),
                    ("appinit-dlls", "AppInit_DLLs")]:
            with self.subTest(key=key):
                self.assertTrue(items[key]["flagged"])
        self.assertNotIn(("debugger-hijack", "notepad.exe"), items)

    def test_appinit_ignored_when_loading_disabled(self):
        items = self.run_with({("HKLM", WIN, "AppInit_DLLs"): r"C:\x\hook.dll",
                               ("HKLM", WIN, "LoadAppInit_DLLs"): 0})
        self.assertNotIn(("appinit-dlls", "AppInit_DLLs"), items)


class TestPathHelpers(unittest.TestCase):
    def test_norm_exe(self):
        with mock.patch.object(scan, "WINDIR", r"c:\windows"):
            self.assertEqual(scan.norm_exe(r'"C:\Program Files\A\a.exe" --x'), r"c:\program files\a\a.exe")
            self.assertEqual(scan.norm_exe(r"\SystemRoot\System32\x.exe"), r"c:\windows\system32\x.exe")
            self.assertEqual(scan.norm_exe(r"\??\C:\x\y.sys"), r"c:\x\y.sys")
            self.assertEqual(scan.norm_exe("D:/Games/a.exe -q"), r"d:\games\a.exe")

    def test_trusted_path(self):
        self.assertTrue(scan.trusted_path(r"d:\program files (x86)\vmware\vmware.exe"))
        self.assertFalse(scan.trusted_path(r"c:\users\bob\appdata\roaming\x.exe"))


if __name__ == "__main__":
    unittest.main()
