"""auditd (#143, from NexusStor issue #6): the log stays small and never stops the appliance, and the rules
load at boot.

The image build merges the rules and checks the syscall names (os/Containerfile); loading them needs the
kernel, so this checks what can go wrong without one: an order that lets a broader watch shadow a
narrower one, a watched directory that does not exist when audit-rules.service runs (auditctl -R stops at
the first failing rule, and -e 2 would never be reached), a halting disk action."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
CONF = ROOT / "os/etc/audit/auditd.conf"
RULES = ROOT / "os/etc/audit/rules.d"


def conf():
    out = {}
    for line in CONF.read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            k, v = (x.strip() for x in line.split("=", 1))
            out[k] = v
    return out


def rules(name="50-nexus.rules"):
    return [l for l in (RULES / name).read_text().splitlines() if l.strip() and not l.startswith("#")]


class AuditdConf(unittest.TestCase):
    def test_log_stays_small(self):
        c = conf()
        self.assertEqual(c["max_log_file_action"], "ROTATE")
        self.assertLessEqual(int(c["max_log_file"]) * int(c["num_logs"]), 50, "MB in /var/log/audit")
        self.assertEqual(c["log_format"], "ENRICHED")
        self.assertEqual(c["log_file"], "/var/log/audit/audit.log")

    def test_never_halts(self):
        c = conf()
        for k in ("space_left_action", "admin_space_left_action", "disk_full_action", "disk_error_action"):
            self.assertIn(c[k], ("SYSLOG", "SUSPEND", "ROTATE", "IGNORE"), k)
        self.assertGreater(int(c["space_left"]), int(c["admin_space_left"]))
        self.assertNotIn("tcp_listen_port", c, "no audit listener on the management network")


class Rules(unittest.TestCase):
    def test_only_watches_and_syscall_rules(self):
        for l in rules():
            self.assertRegex(l, r"^(-w /\S+ -p [rwxa]+ -k [a-z-]+|-a always,exit( -F \S+)+( -S \S+)?( -F \S+)*( -k [a-z-]+)?)$")
            if "-S " in l:
                self.assertRegex(l, r"-F arch=b(32|64) -S ", "a syscall rule needs its arch")

    def test_both_arches(self):
        # the EL10 kernel has CONFIG_IA32_EMULATION=y: 32-bit callers would bypass b64-only rules
        for key in ("time-change", "modules"):
            arches = {re.search(r"arch=(b\d+)", l).group(1) for l in rules() if l.startswith("-a") and l.endswith(key)}
            self.assertEqual(arches, {"b32", "b64"}, key)

    def test_narrow_paths_first(self):
        r = rules()
        idx = {l.split()[1]: i for i, l in enumerate(r) if l.startswith("-w")}
        self.assertLess(idx["/etc/nexus/ssh"], idx["/etc/nexus"])

    def test_services_are_not_audited_on_busy_paths(self):
        # the catalog and the store are written by the services all the time: only login sessions are audited
        busy = [l for l in rules() if "/var/lib/nexus/catalog" in l or "/var/lib/nexus/chunkstore" in l]
        self.assertEqual(len(busy), 2)
        for l in busy:
            self.assertIn("-F auid!=unset", l)
            self.assertIn("-F perm=wa", l)

    def test_watched_directories_exist_at_boot(self):
        # a directory watch (or dir=) fails to load when the directory is missing, and auditctl -R stops at the
        # first failing rule (-e 2 would never be reached). The /var/lib/nexus ones come from tmpfiles, which runs
        # before audit-rules.service (After=systemd-tmpfiles-setup.service); the /etc ones are in the image.
        tmpfiles = (ROOT / "os/tmpfiles.d/nexus.conf").read_text()
        made = set(re.findall(r"^d (\S+) ", tmpfiles, re.M))
        text = "\n".join(rules())
        dirs = re.findall(r"^-w (/var/\S+) ", text, re.M) + re.findall(r"dir=(\S+)", text)
        self.assertEqual(len(dirs), 5)
        for d in dirs:
            self.assertIn(d, made, d)
        for d in ("os/etc/ssh/sshd_config.d", "os/etc/pki/nexus", "os/etc/nexus"):
            self.assertTrue((ROOT / d).is_dir(), d)
        self.assertRegex(tmpfiles, r"(?m)^d /etc/nexus/ssh ")

    def test_locked_last(self):
        names = sorted(p.name for p in RULES.glob("*.rules"))
        self.assertEqual(names[-1], "99-nexus-finalize.rules")
        self.assertEqual(rules(names[-1]), ["-e 2"])

    def test_boot_kargs(self):
        k = (ROOT / "os/greenboot/usr/lib/bootc/kargs.d/10-nexus.toml").read_text()
        self.assertIn('"audit=1"', k)
        self.assertIn('"audit_backlog_limit=8192"', k)

    def test_log_dir_and_presets(self):
        self.assertRegex((ROOT / "os/tmpfiles.d/nexus.conf").read_text(), r"(?m)^d /var/log/audit +0700 +root +root +-$")
        preset = (ROOT / "os/systemd/10-nexus.preset").read_text().splitlines()
        self.assertIn("enable auditd.service", preset)
        self.assertIn("enable audit-rules.service", preset)


if __name__ == "__main__":
    unittest.main()
