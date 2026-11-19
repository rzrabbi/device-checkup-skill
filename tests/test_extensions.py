"""Browser extension discovery with fake Chrome and Firefox profiles (runs on any OS)."""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from helpers import scan


def dump(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)


class TestExtensions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        ud = os.path.join(self.tmp, "Chrome")
        prof = os.path.join(ud, "Default")
        ext = os.path.join(prof, "Extensions")
        # forced by policy, broad access, sensitive permissions
        dump(os.path.join(ext, "aaaa", "1.0_0", "manifest.json"),
             {"name": "Coupon Helper", "version": "1.0", "host_permissions": ["<all_urls>"],
              "permissions": ["cookies", "webRequest"]})
        # normal store extension with a localized name
        dump(os.path.join(ext, "bbbb", "2.0_0", "manifest.json"),
             {"name": "__MSG_appName__", "default_locale": "en", "version": "2.0",
              "permissions": ["storage"]})
        dump(os.path.join(ext, "bbbb", "2.0_0", "_locales", "en", "messages.json"),
             {"appName": {"message": "Good Store Ext"}})
        # added by another program (note, not flag)
        dump(os.path.join(ext, "dddd", "1.0_0", "manifest.json"), {"name": "Vendor PDF", "version": "1"})
        # built-in component (hidden)
        dump(os.path.join(ext, "eeee", "1.0_0", "manifest.json"), {"name": "Built-in", "version": "1"})
        # unpacked (developer mode), outside the Extensions folder
        unpacked = os.path.join(self.tmp, "unpacked")
        dump(os.path.join(unpacked, "manifest.json"),
             {"name": "Dev Helper", "version": "0.1", "content_scripts": [{"matches": ["*://*/*"]}]})
        dump(os.path.join(prof, "Secure Preferences"), {"extensions": {"settings": {
            "aaaa": {"location": 1},
            "bbbb": {"location": 1, "from_webstore": True},
            "cccc": {"location": 4, "path": unpacked},
            "dddd": {"location": 6},
            "eeee": {"location": 5},
        }}})
        dump(os.path.join(prof, "Preferences"), {})
        # Firefox: sideloaded and unsigned, plus a built-in
        ff = os.path.join(self.tmp, "ff", "abc.default")
        dump(os.path.join(ff, "extensions.json"), {"addons": [
            {"id": "side@x", "type": "extension", "location": "winreg-app-global", "signedState": 0,
             "active": True, "defaultLocale": {"name": "Search Helper"},
             "userPermissions": {"origins": ["<all_urls>"]}},
            {"id": "ok@x", "type": "extension", "location": "app-profile", "signedState": 2,
             "active": True, "defaultLocale": {"name": "Normal Addon"},
             "installTelemetryInfo": {"source": "amo"}},
            {"id": "pip@mozilla", "type": "extension", "location": "app-builtin-addons",
             "active": True, "defaultLocale": {"name": "PiP"}},
            {"id": "theme@x", "type": "theme", "location": "app-profile"},
        ]})
        self.patches = [
            mock.patch.object(scan, "chromium_user_dirs", lambda: [("Chrome", ud)]),
            mock.patch.object(scan, "chromium_forced_ids", lambda: {"aaaa": "policy"}),
            mock.patch.object(scan, "firefox_profile_dirs", lambda: [ff]),
            mock.patch.object(scan, "safari_extensions", lambda: []),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_flags_and_notes(self):
        items, hidden = scan.collect_extensions()
        by = {i["name"]: i for i in items}
        self.assertEqual(set(by), {"Coupon Helper", "Good Store Ext", "Vendor PDF", "Dev Helper",
                                   "Search Helper", "Normal Addon"})
        self.assertEqual(hidden, 2)  # Chrome component + Firefox built-in
        self.assertIn("policy", by["Coupon Helper"]["reasons"][0])
        self.assertIn("read cookies (logins)", by["Coupon Helper"]["sensitive_permissions"])
        self.assertTrue(by["Dev Helper"]["flagged"] and by["Dev Helper"]["all_sites_access"])
        self.assertTrue(by["Search Helper"]["flagged"])
        self.assertEqual(len(by["Search Helper"]["reasons"]), 2)
        for clean in ("Good Store Ext", "Normal Addon", "Vendor PDF"):
            self.assertFalse(by[clean]["flagged"], clean)
        self.assertTrue(by["Vendor PDF"]["notes"])
        self.assertIsNotNone(by["Normal Addon"]["store_page"])
        self.assertEqual(items[0]["flagged"], True, "flagged items sort first")

    def test_include_builtin(self):
        items, _ = scan.collect_extensions(include_builtin=True)
        names = {i["name"] for i in items}
        self.assertIn("Built-in", names)
        self.assertIn("PiP", names)


if __name__ == "__main__":
    unittest.main()
