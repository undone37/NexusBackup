"""Unit tests for /usr/libexec/nexus/nexus-net: validation, the keyfiles it writes, the request
protocol (apply, refusals, activation failure → rollback, management change → confirmation or
automatic rollback, a reboot inside the window), drift after a console reconfiguration, the
path-MTU check and console-apply, against a fake nmcli / ip and a fake /sys/class/net.

Run: python3 -m unittest discover -s os/greenboot/tests -v
"""

import contextlib
import importlib.machinery
import io
import importlib.util
import json
import os
import stat
import sys

sys.dont_write_bytecode = True  # never leave __pycache__ in os/greenboot/usr (COPYed into the image)
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "usr/libexec/nexus/nexus-net"

# Fake tool: answers from $FAKE_DIR/answers.json {"<tool> <args...>": [exit, stdout]}, longest
# matching prefix wins; unknown calls exit 0 with no output. Calls are logged.
FAKE = r'''#!PYTHON
import json, os, sys
d = os.environ["FAKE_DIR"]
tool = os.path.basename(sys.argv[0])
line = " ".join([tool] + sys.argv[1:])
with open(os.path.join(d, "calls"), "a") as f:
    f.write(line + "\n")
answers = json.load(open(os.path.join(d, "answers.json")))
best = max((k for k in answers if line == k or line.startswith(k + " ")), key=len, default=None)
rc, out = answers[best] if best else (0, "")
sys.stdout.write(out)
sys.exit(rc)
'''
TOOLS = ("nmcli", "ip")

CONSOLE_MGMT = """[connection]
id=nexus-mgmt
uuid=0b9f6d2c-1111-4222-8333-444455556666
type=ethernet
interface-name=ens3

[ipv4]
method=manual
address1=192.0.2.10/24
gateway=192.0.2.1
"""


def load():
    loader = importlib.machinery.SourceFileLoader("nexus_net", str(SCRIPT))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(mod)
    return mod


def data_config():
    return {"interfaces": [
        {"name": "bond0", "kind": "bond", "ports": ["ens4", "ens5"], "mode": "802.3ad", "mtu": 9000},
        {"name": "bond0.20", "kind": "vlan", "parent": "bond0", "vlan_id": 20, "role": "data", "mtu": 9000,
         "addresses": ["10.0.20.5/24"], "routes": [{"to": "10.30.0.0/16", "via": "10.0.20.1"}]},
        {"name": "ens6", "kind": "ethernet", "role": "replication", "dhcp": True},
    ], "offsite_role": "management"}


def mgmt_config():
    return {"interfaces": [
        {"name": "bond1", "kind": "bond", "ports": ["ens3", "ens7"], "mode": "active-backup", "role": "management",
         "addresses": ["192.0.2.10/24"], "gateway": "192.0.2.1", "dns": ["192.0.2.53"]},
    ]}


class Base(unittest.TestCase):
    def setUp(self):
        self.m = load()
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.fake, self.dir, self.nm, self.sys = t / "fake", t / "net", t / "nm", t / "sys"
        for p in (self.fake, self.dir, self.nm, self.sys):
            p.mkdir()
        for tool in TOOLS:
            p = self.fake / tool
            p.write_text(FAKE.replace("PYTHON", sys.executable))
            p.chmod(0o755)
        for n in ("ens3", "ens4", "ens5", "ens6", "ens7"):
            self.nic(n)
        self.answers = {"ip -j addr show": [0, json.dumps([
            {"ifname": "ens3", "addr_info": [{"family": "inet", "local": "192.0.2.10", "prefixlen": 24, "scope": "global"},
                                            {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"}]}])]}
        self.save()
        (self.nm / "nexus-mgmt.nmconnection").write_text(CONSOLE_MGMT)
        self.allowed = t / "allowed.json"
        self.env = {"NEXUS_NET_NMCLI": str(self.fake / "nmcli"), "NEXUS_NET_IP": str(self.fake / "ip"),
                    "NEXUS_NET_DIR": str(self.dir), "NEXUS_NET_NM_DIR": str(self.nm), "NEXUS_NET_SYS_NET": str(self.sys),
                    "NEXUS_NET_ALLOWED": str(self.allowed), "NEXUS_NET_MTU_INTERVAL": "999999", "FAKE_DIR": str(self.fake)}
        self.old_env = dict(os.environ)
        os.environ.update(self.env)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.old_env)
        self.tmp.cleanup()

    def nic(self, n, mtu=1500, devtype=None):
        d = self.sys / n
        d.mkdir()
        (d / "mtu").write_text(f"{mtu}\n")
        (d / "operstate").write_text("up\n")
        (d / "address").write_text("52:54:00:00:00:01\n")
        (d / "uevent").write_text(f"INTERFACE={n}\n" + (f"DEVTYPE={devtype}\n" if devtype else ""))
        if not devtype:
            (d / "device").mkdir()

    def save(self):
        (self.fake / "answers.json").write_text(json.dumps(self.answers))

    def calls(self):
        p = self.fake / "calls"
        return p.read_text().splitlines() if p.exists() else []

    def request(self, rid, config, old=None, op="apply"):
        r = {"id": rid, "op": op, "by": "alice", "quorum_id": 7}
        if op == "apply":
            r.update(config=config, old=old if old is not None else {"interfaces": [], "offsite_role": "management"})
        (self.dir / f"req-{rid}.json").write_text(json.dumps(r))

    def ops(self):
        return {o["id"]: o for o in json.loads((self.dir / "ops.json").read_text())}

    def status(self):
        return json.loads((self.dir / "status.json").read_text())

    def files(self):
        return sorted(p.name for p in self.nm.iterdir() if not p.name.startswith("."))


class Validation(Base):
    def check(self, cfg, want, had_mgmt=False):
        c = self.m.normalize(cfg)
        with self.assertRaises(self.m.Refused) as e:
            self.m.validate(c, {"ens3", "ens4", "ens5", "ens6"}, "ens3", had_mgmt)
        self.assertIn(want, str(e.exception))

    def test_valid(self):
        c = self.m.normalize(data_config())
        self.m.validate(c, {"ens3", "ens4", "ens5", "ens6"}, "ens3", False)
        self.assertEqual(c["interfaces"][2]["ports"], [])
        self.assertIsNone(c["interfaces"][2]["gateway"])

    def test_refusals(self):
        i = lambda **kw: {"interfaces": [kw]}
        self.check(i(name="ens9", kind="ethernet"), "no network card")
        self.check(i(name="bond0", kind="bond", ports=["ens3"], mode="802.3ad"), "management network card")
        self.check(i(name="bond0", kind="bond", ports=["ens4"], mode="balance-rr"), "bond mode")
        self.check(i(name="v", kind="vlan", parent="ens4", vlan_id=0), "VLAN ID")
        self.check(i(name="ens4", kind="ethernet", mtu=70000), "MTU")
        self.check(i(name="ens4", kind="ethernet", addresses=["10.0.0.5/24"], gateway="10.0.0.1"), "only the management")
        self.check(i(name="ens4", kind="ethernet", addresses=["10.0.0.5/24"], routes=[{"to": "10.1.2.0/16"}]), "not a network")
        self.check(i(name="ens4", kind="ethernet", addresses=["10.0.0.5/24"], routes=[{"to": "0.0.0.0/0", "via": "10.0.0.1"}]), "default route")
        self.check(i(name="ens4", kind="ethernet", addresses=["10.0.0.5/24"], routes=[{"to": "10.1.0.0/16", "via": "10.9.0.1"}]), "not in a subnet")
        self.check(i(name="ens4;x", kind="ethernet"), "interface name")
        self.check({"interfaces": []}, "cannot be removed", had_mgmt=True)
        with self.assertRaises(ValueError):
            self.m.normalize({"interfaces": [{"name": "x", "kind": "bond", "extra": 1}]})
        with self.assertRaises(ValueError):
            self.m.normalize({"interfaces": [{"name": "x", "kind": "bond", "mtu": "9000"}]})

    def test_keyfiles(self):
        k = self.m.keyfiles(self.m.normalize(data_config()))
        self.assertEqual(sorted(k), ["nexus-bond0", "nexus-bond0-port-ens4", "nexus-bond0-port-ens5", "nexus-bond0.20", "nexus-ens6"])
        bond = self.m.ini(k["nexus-bond0"])
        self.assertEqual(bond["connection"]["type"], "bond")
        self.assertEqual(bond["bond"]["mode"], "802.3ad")
        self.assertEqual(bond["ethernet"]["mtu"], "9000")
        self.assertEqual(bond["ipv4"]["method"], "disabled")
        port = self.m.ini(k["nexus-bond0-port-ens4"])
        self.assertEqual((port["connection"]["master"], port["connection"]["slave-type"]), ("bond0", "bond"))
        self.assertFalse(port.has_section("ipv4"))
        vlan = self.m.ini(k["nexus-bond0.20"])
        self.assertEqual((vlan["vlan"]["id"], vlan["vlan"]["parent"]), ("20", "bond0"))
        self.assertEqual(vlan["ipv4"]["address1"], "10.0.20.5/24")
        self.assertEqual(vlan["ipv4"]["route1"], "10.30.0.0/16,10.0.20.1")
        self.assertEqual(vlan["ipv4"]["never-default"], "true")
        self.assertNotIn("gateway", vlan["ipv4"])
        dhcp = self.m.ini(k["nexus-ens6"])
        self.assertEqual((dhcp["ipv4"]["method"], dhcp["ipv4"]["never-default"]), ("auto", "true"))
        self.assertEqual(dhcp["ipv6"]["method"], "disabled")
        # stable UUIDs
        self.assertEqual(k, self.m.keyfiles(self.m.normalize(data_config())))
        m = self.m.keyfiles(self.m.normalize(mgmt_config()))
        self.assertEqual(sorted(m), ["nexus-mgmt", "nexus-mgmt-port-ens3", "nexus-mgmt-port-ens7"])
        mg = self.m.ini(m["nexus-mgmt"])
        self.assertEqual((mg["ipv4"]["gateway"], mg["ipv4"]["dns"]), ("192.0.2.1", "192.0.2.53;"))
        self.assertNotIn("never-default", mg["ipv4"])
        self.assertEqual(mg["connection"]["interface-name"], "bond1")


class Apply(Base):
    def test_data_interfaces(self):
        self.request("a" * 32, data_config())
        self.assertEqual(self.m.tick(), 0)
        op = self.ops()["a" * 32]
        self.assertEqual(op["state"], "done", op)
        self.assertEqual(self.files(), ["nexus-bond0-port-ens4.nmconnection", "nexus-bond0-port-ens5.nmconnection",
                                        "nexus-bond0.20.nmconnection", "nexus-bond0.nmconnection", "nexus-ens6.nmconnection",
                                        "nexus-mgmt.nmconnection"])
        self.assertEqual(stat.S_IMODE((self.nm / "nexus-bond0.nmconnection").stat().st_mode), 0o600)
        self.assertEqual((self.nm / "nexus-mgmt.nmconnection").read_text(), CONSOLE_MGMT, "console profile untouched")
        ups = [c for c in self.calls() if c.startswith("nmcli")]
        self.assertEqual(ups, ["nmcli connection reload",
                               "nmcli --wait 30 connection up id nexus-bond0",
                               "nmcli --wait 30 connection up id nexus-ens6",
                               "nmcli --wait 30 connection up id nexus-bond0.20"])
        st = self.status()
        self.assertEqual(st["config"], self.m.normalize(data_config()))
        self.assertEqual(st["management"], {"ifname": "ens3", "source": "console"})
        self.assertEqual({d["name"]: d["kind"] for d in st["devices"]}["ens4"], "nic")
        self.assertEqual(st["devices"][0]["addresses"], ["192.0.2.10/24"])
        self.assertTrue(stat.S_IMODE((self.dir / "status.json").stat().st_mode) & 0o004)
        self.assertFalse(list(self.dir.glob("req-*")))
        # the same again: nothing to change; then a stale `old` is refused
        self.request("b" * 32, data_config(), old=st["config"])
        self.m.tick()
        self.assertEqual(self.ops()["b" * 32]["detail"], "nothing to change")
        self.request("c" * 32, {"interfaces": []})
        self.m.tick()
        self.assertEqual(self.ops()["c" * 32]["state"], "refused")
        self.assertIn("changed since", self.ops()["c" * 32]["error"])
        # removing them: files gone, console profile stays
        self.request("d" * 32, {"interfaces": []}, old=st["config"])
        self.m.tick()
        self.assertEqual(self.ops()["d" * 32]["state"], "done")
        self.assertEqual(self.files(), ["nexus-mgmt.nmconnection"])

    def test_activation_failure_rolls_back(self):
        self.answers["nmcli --wait 30 connection up id nexus-ens6"] = [4, "Error: no carrier"]
        self.save()
        self.request("a" * 32, data_config())
        self.m.tick()
        op = self.ops()["a" * 32]
        self.assertEqual(op["state"], "error")
        self.assertIn("previous configuration restored", op["error"])
        self.assertEqual(self.files(), ["nexus-mgmt.nmconnection"])
        self.assertEqual(self.status()["config"]["interfaces"], [])

    def test_management_confirmed(self):
        rid = "e" * 32
        (self.dir / "confirm.json").write_text(json.dumps({"id": rid, "keep": True, "by": "bob"}))
        self.request(rid, mgmt_config())
        self.m.tick()
        op = self.ops()[rid]
        self.assertEqual(op["state"], "done", op)
        self.assertIn("confirmed by bob", op["detail"])
        self.assertIn("bond1", (self.nm / "nexus-mgmt.nmconnection").read_text())
        self.assertFalse((self.dir / "pending.json").exists())
        st = self.status()
        self.assertEqual(st["management"], {"ifname": "bond1", "source": "config"})
        # once managed here the management interface cannot be dropped
        self.request("f" * 32, {"interfaces": []}, old=st["config"])
        self.m.tick()
        self.assertEqual(self.ops()["f" * 32]["state"], "refused")

    def test_management_not_confirmed(self):
        os.environ["NEXUS_NET_CONFIRM_SECS"] = "1"
        rid = "e" * 32
        self.request(rid, mgmt_config())
        self.m.tick()
        op = self.ops()[rid]
        self.assertEqual(op["state"], "rolled_back", op)
        self.assertIn("not confirmed", op["detail"])
        self.assertEqual((self.nm / "nexus-mgmt.nmconnection").read_text(), CONSOLE_MGMT)
        self.assertEqual(self.files(), ["nexus-mgmt.nmconnection"])
        self.assertEqual(self.status()["config"]["interfaces"], [])
        self.assertIsNone(self.status()["pending"])
        # the restored profile was activated again
        self.assertEqual([c for c in self.calls() if "up id" in c][-1], "nmcli --wait 30 connection up id nexus-mgmt")

    def test_management_reverted(self):
        rid = "e" * 32
        (self.dir / "confirm.json").write_text(json.dumps({"id": rid, "keep": False, "by": "bob"}))
        self.request(rid, mgmt_config())
        self.m.tick()
        self.assertEqual(self.ops()[rid]["detail"], "reverted by bob")
        self.assertEqual((self.nm / "nexus-mgmt.nmconnection").read_text(), CONSOLE_MGMT)

    def test_reboot_inside_window(self):
        # a run that ended inside the window: the new keyfiles are active, pending.json remains
        new = self.m.normalize(mgmt_config())
        want = self.m.keyfiles(new)
        backup = {"nexus-mgmt": CONSOLE_MGMT}
        for n, t in want.items():
            (self.nm / f"{n}.nmconnection").write_text(t)
        rec = {"id": "9" * 32, "op": "apply", "by": "alice", "quorum_id": None, "params": {}, "created": 1,
               "state": "confirming", "error": None, "detail": None}
        self.m.write_json(str(self.dir / "pending.json"), {
            "id": "9" * 32, "by": "alice", "deadline": int(time.time()) - 5, "backup": backup,
            "prev": {"config": self.m.normalize(None), "files": {}}, "config": new, "files": {}, "rec": rec}, 0o600)
        self.m.tick()
        self.assertEqual(self.ops()["9" * 32]["state"], "rolled_back")
        self.assertEqual(self.files(), ["nexus-mgmt.nmconnection"])
        self.assertEqual((self.nm / "nexus-mgmt.nmconnection").read_text(), CONSOLE_MGMT)

    def test_console_reconfiguration_resets(self):
        self.request("a" * 32, data_config())
        self.m.tick()
        (self.nm / "nexus-ens6.nmconnection").unlink()  # nexus-setup removed the profiles
        self.m.tick()
        st = self.status()
        self.assertEqual(st["config"]["interfaces"], [])
        self.assertIsNotNone(st["reset"])

    def test_bad_requests_ignored(self):
        (self.dir / f"req-{'a' * 32}.json").write_text(json.dumps({"id": "a" * 32, "op": "rm", "by": "x"}))
        (self.dir / f"req-{'b' * 32}.json").write_text("{")
        self.m.tick()
        self.assertFalse(list(self.dir.glob("req-*")))
        self.assertEqual(json.loads((self.dir / "ops.json").read_text()) if (self.dir / "ops.json").exists() else [], [])


class Mtu(Base):
    def test_mtu_check(self):
        self.allowed.write_text(json.dumps({"endpoints": [], "roles": {
            "data": {"iface": "bond0.20", "endpoints": [
                {"addr": "10.0.20.7", "proto": "tcp", "port": 8006}, {"addr": "10.0.20.7", "proto": "tcp", "port": 22},
                {"addr": "10.30.0.9", "proto": "tcp", "port": 8006}, {"addr": "10.30.0.10", "proto": "tcp", "port": 8006}]},
            "offsite": {"iface": None, "endpoints": [{"addr": "198.51.100.40", "proto": "tcp", "port": 23}]}}}))
        self.nic("bond0.20", mtu=9000, devtype="vlan")
        self.answers.update({
            "ip -j route get 10.0.20.7": [0, '[{"dst":"10.0.20.7","dev":"bond0.20"}]'],
            "ip -j route get 10.30.0.9": [0, '[{"dst":"10.30.0.9","dev":"bond0.20"}]'],
            "ip -j route get 10.30.0.10": [0, '[{"dst":"10.30.0.10","dev":"ens3"}]'],
            "ip -j route get 198.51.100.40": [2, ""],
        })
        self.save()

        def probe(addr, size):
            if addr == "10.30.0.10":
                return "timeout"
            if addr == "10.30.0.9" and size > 1500:
                return "too_big"
            return "ok"

        r = self.m.mtu_check(self.m.devices(), probe)["results"]
        by = {x["addr"]: x for x in r}
        self.assertEqual(len(r), 4)
        self.assertEqual((by["10.0.20.7"]["result"], by["10.0.20.7"]["mtu"]), ("ok", 9000))
        self.assertEqual(by["10.30.0.9"]["result"], "mismatch")
        self.assertTrue(1492 <= by["10.30.0.9"]["path_mtu"] <= 1500, by["10.30.0.9"])
        self.assertEqual((by["10.30.0.10"]["result"], by["10.30.0.10"]["dev"], by["10.30.0.10"]["expected_dev"]),
                         ("no_reply", "ens3", "bond0.20"))
        self.assertEqual(by["198.51.100.40"]["result"], "no_route")

    def test_requested_check_in_tick(self):
        self.request("a" * 32, None, op="mtu_check")
        os.environ["NEXUS_NET_MTU_INTERVAL"] = "999999"
        self.m.tick()
        self.assertEqual(self.status()["mtu"]["results"], [])
        self.assertEqual(self.ops()["a" * 32]["state"], "done")

    def test_ping_loopback(self):
        r = self.m.ping("127.0.0.1", 1000, timeout=1.0)
        if r.startswith("error"):
            self.skipTest(f"no ICMP socket here: {r}")
        self.assertEqual(r, "ok")
        self.assertEqual(self.m.ping("127.0.0.1", 70000, timeout=1.0), "too_big")


class Console(Base):
    def test_console_apply(self):
        cfg = {"interfaces": [
            {"name": "bond0", "kind": "bond", "ports": ["ens3", "ens4"], "mode": "802.3ad", "mtu": 9000},
            {"name": "bond0.10", "kind": "vlan", "parent": "bond0", "vlan_id": 10, "role": "management",
             "addresses": ["192.0.2.10/24"], "gateway": "192.0.2.1"}]}
        # an interface from the web UI is replaced
        self.request("a" * 32, {"interfaces": [{"name": "ens6", "kind": "ethernet", "role": "data", "dhcp": True}]})
        self.m.tick()
        self.assertIn("nexus-ens6.nmconnection", self.files())
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(self.m.main(["nexus-net", "console-apply", json.dumps(cfg)]), 0)
        self.assertIn("nexus-mgmt", out.getvalue())
        self.assertEqual(self.files(), ["nexus-bond0-port-ens3.nmconnection", "nexus-bond0-port-ens4.nmconnection",
                                        "nexus-bond0.nmconnection", "nexus-mgmt.nmconnection"])
        self.assertIn("bond0.10", (self.nm / "nexus-mgmt.nmconnection").read_text())
        self.m.tick()
        self.assertEqual(self.status()["management"], {"ifname": "bond0.10", "source": "config"})
        bad = {"interfaces": [{"name": "ens6", "kind": "ethernet", "role": "data", "dhcp": True}]}
        self.assertEqual(self.m.main(["nexus-net", "console-apply", json.dumps(bad)]), 2)


if __name__ == "__main__":
    unittest.main()
