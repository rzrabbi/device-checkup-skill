"""Linux/macOS startup-location parsers with fake files and command output (runs on any OS)."""
import os
import shutil
import tempfile
import unittest
from unittest import mock

from helpers import j, scan


class FakeHome(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        real = os.path.expanduser
        self.patch = mock.patch.object(
            scan.os.path, "expanduser",
            lambda p: p.replace("~", self.home, 1) if p.startswith("~") else real(p))
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        shutil.rmtree(self.home, ignore_errors=True)

    def write(self, rel, text):
        p = os.path.join(self.home, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p

    def mine(self, items):
        root = os.path.realpath(self.home)
        return [i for i in items if os.path.realpath(i["source"]).startswith(root)
                or os.path.realpath(i["name"]).startswith(root)]


class TestSshKeys(FakeHome):
    def test_keys_parsed_and_forced_command_flagged(self):
        self.write(".ssh/authorized_keys",
                   "# comment\n"
                   "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGood bob@laptop\n"
                   'command="/bin/sh -c x",no-pty ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB other\n'
                   "not a key line\n")
        keys = {k["name"]: k for k in self.mine(scan.ssh_authorized_keys())}
        self.assertEqual(set(keys), {"bob@laptop", "other"})
        self.assertFalse(keys["bob@laptop"]["flagged"])
        self.assertTrue(keys["other"]["flagged"])
        self.assertNotIn("AAAAC3NzaC1lZDI1NTE5AAAAIGood", keys["bob@laptop"]["command"],
                         "full key material should not be echoed")


class TestShellStartup(FakeHome):
    def test_fingerprint_and_flags(self):
        self.write(".bashrc", j("export PATH=$PATH:~/bin\nalias su", "do='sudo -E /tmp/.x'\n"))
        self.write(".profile", "# normal\n[ -f ~/.bashrc ] && . ~/.bashrc\n")
        items = {os.path.basename(i["name"]): i for i in self.mine(scan.shell_startup_files())}
        self.assertTrue(items[".bashrc"]["flagged"])
        self.assertFalse(items[".profile"]["flagged"])
        self.assertTrue(items[".profile"]["system"])
        self.assertTrue(items[".profile"]["command"].startswith("sha256:"))

    def test_fingerprint_changes_when_file_edited(self):
        p = os.path.normpath(self.write(".zshrc", "echo one\n"))

        def fingerprint():
            return {os.path.normpath(i["name"]): i["command"] for i in scan.shell_startup_files()}[p]

        before = fingerprint()
        self.write(".zshrc", "echo two\n")
        after = fingerprint()
        self.assertNotEqual(before, after)


BTM = """========================
 Records for UID 501 : abc
========================
 ServiceManagement Items:
 #1:
                 UUID: 1
                 Name: Docker
       Developer Name: Docker Inc
                 Type: app (0x2)
          Disposition: [enabled, allowed, visible, notified] (11)
           Identifier: 2.com.docker.docker
                  URL: file:///Applications/Docker.app/
 #2:
                 UUID: 2
                 Name: updater
                 Type: legacy daemon (0x10010)
          Disposition: [enabled, allowed, visible, notified] (11)
           Identifier: 16.com.example.updater
      Executable Path: /Users/bob/Library/.hidden/updater
 #3:
                 UUID: 3
                 Name: Docker Inc
                 Type: developer (0x20)
          Disposition: [enabled, allowed, visible, notified] (11)
           Identifier: Docker Inc
"""


def fake_run(outputs):
    def run(cmd, timeout=120, shell=False, cwd=None):
        for prefix, result in outputs.items():
            if tuple(cmd[:len(prefix)]) == prefix:
                return result
        return 1, "", "not found"
    return run


class TestMacParsers(unittest.TestCase):
    def test_login_items(self):
        with mock.patch.object(scan, "run", fake_run({("sfltool", "dumpbtm"): (0, BTM, "")})):
            items = {i["name"]: i for i in scan.mac_login_items()}
        self.assertEqual(set(items), {"Docker", "updater"})
        self.assertFalse(items["Docker"]["flagged"])
        self.assertTrue(items["updater"]["flagged"])

    def test_login_items_not_readable_goes_to_not_checked(self):
        scan.NOT_CHECKED.clear()
        with mock.patch.object(scan, "run", fake_run({("sfltool",): (1, "", "requires root")})):
            self.assertEqual(scan.mac_login_items(), [])
        self.assertTrue(any("Login Items" in n["what"] for n in scan.NOT_CHECKED))
        scan.NOT_CHECKED.clear()

    def test_profiles(self):
        outputs = {
            ("profiles", "list"): (0, "_computerlevel[1] attribute: profileIdentifier: com.example.search\n", ""),
            ("profiles", "status"): (0, "Enrolled via DEP: No\nMDM enrollment: Yes\n", ""),
        }
        with mock.patch.object(scan, "run", fake_run(outputs)):
            items = scan.mac_profiles()
        kinds = {i["kind"] for i in items}
        self.assertEqual(kinds, {"config-profile", "mdm-enrollment"})
        self.assertTrue(all(i["flagged"] for i in items))


class TestRkhunter(unittest.TestCase):
    def test_parse(self):
        text = ("Checking system commands...\n"
                "Warning: The file properties have changed:\n"
                "         File: /usr/bin/lwp-request\n"
                "         Current hash: abc\n"
                "Checking for rootkits...\n"
                "Warning: Hidden directory found: /etc/.java\n")
        w = scan.parse_rkhunter(text)
        self.assertEqual(len(w), 2)
        self.assertEqual(w[0]["details"], ["File: /usr/bin/lwp-request", "Current hash: abc"])
        self.assertEqual(w[1]["details"], [])


if __name__ == "__main__":
    unittest.main()
