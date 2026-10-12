"""Unit tests for /usr/libexec/nexus/nexus-disks: the lsblk / smartctl / mdstat / mdadm parsers
(fixtures in fixtures/disks: lsblk -J -b -O and smartctl 7.4 -j output, /proc/mdstat and
mdadm --detail text), roles, the request protocol and the layout operations against fake tools
(which disks are refused, which commands run).

Run: python3 -m unittest discover -s os/greenboot/tests -v
"""

import importlib.machinery
import importlib.util
import json
import os
import stat
import sys

sys.dont_write_bytecode = True  # never leave __pycache__ in os/greenboot/usr (COPYed into the image)
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "usr/libexec/nexus/nexus-disks"
FIX = HERE / "fixtures/disks"

# Fake tool: answers from $FAKE_DIR/answers.json {"<tool> <args...>": [exit, stdout]}, longest
# matching prefix wins; unknown calls exit 0 with no output. Calls are logged (an mkfs protofile
# argument with its contents).
FAKE = r'''#!PYTHON
import json, os, sys
d = os.environ["FAKE_DIR"]
tool = os.path.basename(sys.argv[0])
line = " ".join([tool] + sys.argv[1:])
with open(os.path.join(d, "calls"), "a") as f:
    f.write(line + "\n")
    for a in sys.argv[1:]:
        if os.path.basename(a) == ".mkfs-proto":
            f.write("PROTO " + open(a).read().replace("\n", "|") + "\n")
answers = json.load(open(os.path.join(d, "answers.json")))
best = max((k for k in answers if line == k or line.startswith(k + " ")), key=len, default=None)
rc, out = answers[best] if best else (0, "")
sys.stdout.write(out)
sys.exit(rc)
'''
TOOLS = ("lsblk", "smartctl", "mdadm", "wipefs", "blkid", "mkfs.xfs", "xfs_growfs", "systemctl")


def load():
    loader = importlib.machinery.SourceFileLoader("nexus_disks", str(SCRIPT))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(mod)
    return mod


def fixture(name):
    return (FIX / name).read_text()


def empty_lsblk():
    """The fixture host before the data array: the six HDDs are blank, no md126."""
    j = json.loads(fixture("lsblk.json"))
    for n in j["blockdevices"]:
        if (n.get("model") or "").startswith("WDC"):
            n.update(fstype=None, uuid=None, label=None)
            n.pop("children", None)
    return json.dumps(j)


MDSTAT_NO_DATA = "\n\n".join(b for b in fixture("mdstat").split("\n\n") if "md126" not in b) + "\n"
MDSTAT_CLEAN = fixture("mdstat").replace("sdg[4] sdf[3](F) sde[2] sdd[1] sdc[0]", "sdf[3] sde[2] sdd[1] sdc[0]") \
    .replace("[4/3] [UUU_]", "[4/4] [UUUU]") \
    .replace("      [====>................]  recovery = 24.8% (969287680/3906823296) finish=301.2min speed=162543K/sec\n", "")
DETAIL_CLEAN = fixture("mdadm-detail-md126").replace("clean, degraded, recovering", "clean") \
    .replace("    Rebuild Status : 24% complete\n\n", "") \
    .replace("       4       8       96        3      spare rebuilding   /dev/sdg\n\n       3       8       80        -      faulty   /dev/sdf\n",
             "       3       8       80        3      active sync   /dev/sdf\n")
DATA_UUID = "3f0c1a2b:4d5e6f70:81920a1b:2c3d4e5f"
SYS_UUID = "9a8b7c6d:5e4f3a2b:1c0d9e8f:7a6b5c4d"


class Parsers(unittest.TestCase):
    def setUp(self):
        self.m = load()

    def test_lsblk(self):
        tree = self.m.parse_lsblk(fixture("lsblk.json"))
        self.assertEqual([d["name"] for d in tree], ["sda", "sdb", "sdc", "sdd", "sde", "sdf", "sdg", "sdh", "nvme0n1", "nvme1n1", "sdi"])
        self.assertEqual(self.m.disk_type(tree[0]), "ssd")
        self.assertEqual(self.m.disk_type(tree[2]), "hdd")
        self.assertEqual(self.m.disk_type(tree[8]), "nvme")
        self.assertEqual(self.m.owners(tree)["sda3"], "sda")

    def test_mdstat(self):
        s = self.m.parse_mdstat(fixture("mdstat"))
        self.assertEqual(sorted(s), ["md125", "md126", "md127"])
        a = s["md126"]
        self.assertEqual((a["level"], a["action"], a["progress"], a["finish_min"], a["speed_kbs"], a["status"]),
                         ("raid6", "recovery", 24.8, 301.2, 162543, "UUU_"))
        self.assertIn({"dev": "sdf", "slot": 3, "flag": "F"}, a["members"])
        self.assertIsNone(s["md127"]["action"])
        m = self.m.parse_mdstat(fixture("mdstat-misc"))
        self.assertEqual((m["md127"]["action"], m["md127"]["progress"]), ("reshape", 47.3))
        self.assertEqual((m["md1"]["level"], m["md1"]["action"], m["md1"]["progress"]), ("raid10", "resync", 0.0))
        self.assertEqual(m["md2"]["status"], "UUU_")
        self.assertFalse(m["md0"]["active"])
        self.assertEqual(m["md0"]["members"], [{"dev": "sdx", "slot": 0, "flag": "S"}])

    def test_mdadm_detail(self):
        d = self.m.parse_mdadm_detail(fixture("mdadm-detail-md126"))
        self.assertEqual(d["level"], "raid6")
        self.assertEqual(d["state_words"], ["clean", "degraded", "recovering"])
        self.assertEqual((d["raid_devices"], d["active_devices"], d["failed_devices"], d["spare_devices"]), (4, 3, 1, 1))
        self.assertEqual(d["md_name"], "nexus:nexus-data")
        self.assertEqual(d["uuid"], DATA_UUID)
        self.assertEqual(d["used_dev_size"], 3906823296 * 1024)
        self.assertEqual(d["bitmap"], "Internal")
        self.assertEqual(d["progress"], 24.0)
        self.assertEqual(d["devices"][3], {"number": 4, "raid_device": 3, "state": ["spare", "rebuilding"], "dev": "/dev/sdg"})
        self.assertEqual(d["devices"][4], {"number": 3, "raid_device": None, "state": ["faulty"], "dev": "/dev/sdf"})
        self.assertIsNone(self.m.parse_mdadm_detail(fixture("mdadm-detail-md125"))["bitmap"])

    def test_smart_ata(self):
        s = self.m.parse_smart(json.loads(fixture("smart-hdd-pending.json")), 192)
        self.assertTrue(s["available"])
        self.assertEqual(s["health"], "passed")
        self.assertEqual((s["reallocated"], s["pending"], s["offline_uncorrectable"]), (24, 8, 0))
        self.assertEqual((s["temperature"], s["power_on_hours"]), (38, 15523))
        self.assertEqual(s["self_test"], {"running": False, "remaining": None,
                                          "last": {"type": "Short offline", "status": "Completed: read failure", "passed": False, "hours": 15519}})
        self.assertEqual(len(s["attributes"]), 8)
        self.assertIsNone(s["percentage_used"])

    def test_smart_failing_and_running(self):
        j = json.loads(fixture("smart-hdd-pending.json"))
        j["smart_status"]["passed"] = False
        j["ata_smart_data"]["self_test"]["status"] = {"value": 249, "string": "in progress, 90% remaining", "remaining_percent": 90}
        s = self.m.parse_smart(j, 8 | 64)
        self.assertEqual(s["health"], "failed")
        self.assertEqual((s["self_test"]["running"], s["self_test"]["remaining"]), (True, 90))

    def test_smart_nvme(self):
        s = self.m.parse_smart(json.loads(fixture("smart-nvme.json")), 0)
        self.assertEqual((s["health"], s["percentage_used"], s["media_errors"], s["critical_warning"], s["available_spare"]),
                         ("passed", 3, 0, 0, 100))
        self.assertEqual((s["temperature"], s["power_on_hours"]), (41, 1488))
        self.assertEqual(s["self_test"]["last"], {"type": "Short", "status": "Completed without error", "passed": True, "hours": 1462})
        self.assertIsNone(s["pending"])

    def test_smart_unavailable(self):
        s = self.m.parse_smart(json.loads(fixture("smart-virtio.json")), 1)
        self.assertFalse(s["available"])
        self.assertIn("Unable to detect device type", s["error"])
        s = self.m.parse_smart(json.loads(fixture("smart-standby.json")), 2)
        self.assertTrue(s["standby"])


class Host(unittest.TestCase):
    """The helper against fake tools in a temp dir."""

    def setUp(self):
        self.m = load()
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.fake, self.dir, self.dev, self.units = t / "fake", t / "disks", t / "dev", t / "units"
        for p in (self.fake, self.dir, self.dev / "md", self.units):
            p.mkdir(parents=True)
        self.store = t / "store"
        self.store.mkdir()
        (self.store / "acme").mkdir()  # directories only: empty
        for tool in TOOLS:
            p = self.fake / tool
            p.write_text(FAKE.replace("PYTHON", sys.executable))
            p.chmod(0o755)
        self.answers = {
            "lsblk": [0, fixture("lsblk.json")],
            "mdadm --detail": [1, ""],
            "smartctl": [1, fixture("smart-virtio.json")],
            "smartctl -j -a -n standby /dev/sdf": [192, fixture("smart-hdd-pending.json")],
            "smartctl -j -a -n standby /dev/nvme0n1": [0, fixture("smart-nvme.json")],
            "blkid": [0, "0e7d8c9b-aaaa-4bbb-8ccc-1234567890ab\n"],
            "systemctl is-active --quiet nexus-replicad.service": [3, ""],
        }
        for md in ("md125", "md126", "md127"):
            self.answers[f"mdadm --detail {self.dev}/{md}"] = [0, fixture(f"mdadm-detail-{md}")]
        self.save()
        self.mdstat = t / "mdstat"
        self.mdstat.write_text(fixture("mdstat"))
        self.env = {f"NEXUS_DISKS_{self.m.tool_key(x)}": str(self.fake / x) for x in TOOLS}
        self.env.update({
            "NEXUS_DISKS_DIR": str(self.dir), "NEXUS_DISKS_DEV": str(self.dev), "NEXUS_DISKS_MDSTAT": str(self.mdstat),
            "NEXUS_DISKS_UNIT_DIR": str(self.units), "NEXUS_DISKS_STORE": str(self.store),
            "NEXUS_DISKS_STORE_USER": "root", "FAKE_DIR": str(self.fake),
        })
        self.old_env = dict(os.environ)
        os.environ.update(self.env)
        # the fixture mounts the data array at the appliance path
        self.lsblk(fixture("lsblk.json"))

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.old_env)
        self.tmp.cleanup()

    def save(self):
        (self.fake / "answers.json").write_text(json.dumps(self.answers))

    def lsblk(self, text):
        self.answers["lsblk"] = [0, text.replace("/var/lib/nexus/chunkstore", str(self.store))]
        self.save()

    def calls(self):
        p = self.fake / "calls"
        return p.read_text().splitlines() if p.exists() else []

    def scan(self, **kw):
        return self.m.scan({}, **kw)

    def disk(self, st, name):
        return next(d for d in st["disks"] if d["name"] == name)

    def array(self, st, name):
        return next(a for a in st["arrays"] if a["name"] == name)

    # ------------------------------------------------------------ inventory

    def test_roles_and_arrays(self):
        st = self.scan()
        roles = {d["name"]: d["role"] for d in st["disks"]}
        self.assertEqual(roles, {"sda": "system", "sdb": "system", "sdc": "data", "sdd": "data", "sde": "data", "sdf": "data",
                                 "sdg": "data", "sdh": "empty", "nvme0n1": "empty", "nvme1n1": "empty", "sdi": "in_use"})
        self.assertEqual(self.disk(st, "sdi")["why"], "has partitions")
        a = self.array(st, "md126")
        self.assertEqual((a["role"], a["state"], a["degraded"], a["action"], a["progress"], a["finish_minutes"]),
                         ("data", "recovering", True, "recover", 24.8, 301.2))
        self.assertEqual({m["serial"]: m["state"] for m in a["members"]},
                         {"WD-WX12D3456701": "active", "WD-WX12D3456702": "active", "WD-WX12D3456703": "active",
                          "WD-WX12D3456705": "rebuilding", "WD-WX12D3456704": "faulty"})
        self.assertEqual(a["fs"]["type"], "xfs")
        self.assertEqual((self.array(st, "md127")["role"], self.array(st, "md125")["role"]), ("system", "system"))
        self.assertEqual(self.array(st, "md127")["state"], "clean")
        self.assertEqual(st["store"]["array"], "md126")
        self.assertEqual(st["store"]["array_uuid"], DATA_UUID)
        self.assertTrue(st["store"]["empty"])

    def test_smart_cached_and_forced(self):
        st = self.scan(now=1000)
        sdf = self.disk(st, "sdf")["smart"]
        self.assertEqual((sdf["pending"], sdf["checked"]), (8, 1000))
        self.assertFalse(self.disk(st, "sdg")["smart"]["available"])
        n = sum(c.startswith("smartctl") for c in self.calls())
        self.assertEqual(n, 11)
        st2 = self.m.scan(st, now=1600)
        self.assertEqual(sum(c.startswith("smartctl") for c in self.calls()), n)  # within the interval: cached
        self.assertEqual(self.disk(st2, "sdf")["smart"]["checked"], 1000)
        self.m.scan(st2, now=1700, force_smart=True)
        self.assertEqual(sum(c.startswith("smartctl") for c in self.calls()), 2 * n)

    def test_standby_keeps_last_reading(self):
        st = self.scan(now=1000)
        self.answers["smartctl -j -a -n standby /dev/sdf"] = [2, fixture("smart-standby.json")]
        self.save()
        s = self.disk(self.m.scan(st, now=1000 + 7200), "sdf")["smart"]
        self.assertEqual((s["pending"], s["standby"]), (8, True))

    def test_signature_makes_disk_in_use(self):
        self.answers["wipefs --noheadings --output TYPE /dev/sdh"] = [0, "xfs\n"]
        self.save()
        d = self.disk(self.scan(), "sdh")
        self.assertEqual((d["role"], d["why"]), ("in_use", "contains a signature: xfs"))

    def test_store_with_files_is_not_empty(self):
        (self.store / "acme" / "chunk").write_bytes(b"x")
        self.assertFalse(self.scan()["store"]["empty"])

    # ------------------------------------------------------------ requests

    def test_parse_request(self):
        ok = {"id": "0" * 32, "op": "create_array", "by": "alice", "quorum_id": 3, "role": "data", "level": "raid6",
              "disks": ["A1", "B2", "C3", "D4"]}
        self.assertEqual(self.m.parse_request(json.dumps(ok))["disks"], ["A1", "B2", "C3", "D4"])
        bad = [
            {**ok, "id": "../x"}, {**ok, "op": "format"}, {**ok, "by": "a/b"}, {**ok, "quorum_id": True},
            {**ok, "disks": ["A1", "A1"]}, {**ok, "disks": ["A 1", "B2"]}, {**ok, "role": "metadata", "level": "raid6"},
            {**ok, "level": "raid0"}, {"id": "0" * 32, "op": "selftest", "by": "a", "disk": "A1", "type": "conveyance"},
            {"id": "0" * 32, "op": "grow", "by": "a", "array": "md126", "disk": "A1"},
        ]
        for b in bad:
            with self.assertRaises(ValueError, msg=b):
                self.m.parse_request(json.dumps(b))
        with self.assertRaises(ValueError):
            self.m.parse_request("x" * 5000)

    def req(self, **kw):
        kw.setdefault("id", os.urandom(16).hex())
        kw.setdefault("by", "alice")
        kw.setdefault("quorum_id", 7)
        p = self.dir / f"req-{kw['id']}.json"
        p.write_text(json.dumps(kw))
        return kw["id"]

    def tick(self):
        self.assertEqual(self.m.tick(), 0)
        ops = {o["id"]: o for o in json.loads((self.dir / "ops.json").read_text())}
        return ops

    def test_tick_consumes_requests_and_writes_readable_files(self):
        rid = self.req(op="scan")
        (self.dir / ("req-" + "f" * 32 + ".json")).write_text("{not json")
        ops = self.tick()
        self.assertEqual(list(self.dir.glob("req-*")), [])
        self.assertEqual(ops[rid]["state"], "done")
        for n in ("status.json", "ops.json"):
            self.assertEqual(stat.S_IMODE((self.dir / n).stat().st_mode), 0o644)
        st = json.loads((self.dir / "status.json").read_text())
        self.assertEqual(st["smart_scanned"], st["scanned"])

    def test_selftest(self):
        self.answers["smartctl -t short /dev/nvme0n1"] = [0, "Short self-test started.\nPlease wait 2 minutes for test to complete.\n"]
        self.save()
        rid = self.req(op="selftest", disk="S7DNNJ0W100001X", type="short")
        ops = self.tick()
        self.assertEqual(ops[rid]["state"], "done", ops[rid])
        self.assertIn("about 2 minutes", ops[rid]["detail"])
        self.assertIn("smartctl -t short /dev/nvme0n1", self.calls())

    # ------------------------------------------------------------ create

    def fresh(self):
        self.lsblk(empty_lsblk())
        self.mdstat.write_text(MDSTAT_NO_DATA)
        (self.dev / "md" / "nexus-data").write_text("")
        self.answers["systemctl is-active --quiet nexus-scheduler.service"] = [0, ""]
        self.save()

    HDDS = ["WD-WX12D3456701", "WD-WX12D3456702", "WD-WX12D3456703", "WD-WX12D3456704"]

    def create(self, **kw):
        return self.req(**{"op": "create_array", "role": "data", "level": "raid6", "disks": self.HDDS, **kw})

    def test_create_array(self):
        self.fresh()
        rid = self.create()
        ops = self.tick()
        self.assertEqual(ops[rid]["state"], "done", ops[rid])
        calls = self.calls()
        create = next(c for c in calls if c.startswith("mdadm --create"))
        self.assertEqual(create, f"mdadm --create {self.dev}/md/nexus-data --run --name=nexus-data --metadata=1.2 --level=raid6 "
                                 "--raid-devices=4 --bitmap=internal /dev/sdc /dev/sdd /dev/sde /dev/sdf")
        self.assertIn("PROTO nexus-store|0 0|d--700 0 0|$|", calls)
        self.assertTrue(any(c.startswith("mkfs.xfs -q -L nexus-data -p ") for c in calls))
        order = [c for c in calls if c.startswith("systemctl") and "is-active --quiet nexus" not in c]
        self.assertEqual(order, ["systemctl --no-ask-password stop nexus-scheduler.service",
                                 "systemctl --no-ask-password daemon-reload",
                                 "systemctl --no-ask-password enable --now var-lib-nexus-chunkstore.mount",
                                 "systemctl is-active --quiet var-lib-nexus-chunkstore.mount",
                                 "systemctl --no-ask-password start nexus-scheduler.service"])
        unit = (self.units / "var-lib-nexus-chunkstore.mount").read_text()
        self.assertIn("What=/dev/disk/by-uuid/0e7d8c9b-aaaa-4bbb-8ccc-1234567890ab\n", unit)
        self.assertIn(f"Where={self.store}\n", unit)
        self.assertIn("context=system_u:object_r:nexus_store_t:s0", unit)
        self.assertIn("RequiredBy=nexus-scheduler.service nexus-replicad.service", unit)
        self.assertFalse((self.dir / ".mkfs-proto").exists())

    def assert_refused(self, rid, text):
        ops = self.tick()
        self.assertEqual(ops[rid]["state"], "refused", ops[rid])
        self.assertIn(text, ops[rid]["error"])
        self.assertFalse(any(c.startswith(("mdadm --create", "mkfs", "systemctl --no-ask-password stop")) for c in self.calls()))

    def test_create_refuses_system_disk(self):
        self.fresh()
        self.assert_refused(self.create(disks=["S6PNNM0T401234A", *self.HDDS[1:]]), "is not empty: system")

    def test_create_refuses_partitioned_disk(self):
        self.fresh()
        self.assert_refused(self.create(disks=["ZFL1A2B3", *self.HDDS[1:]]), "has partitions")

    def test_create_refuses_signature(self):
        self.fresh()
        self.answers["wipefs --noheadings --output TYPE /dev/sdd"] = [0, "LVM2_member\n"]
        self.save()
        self.assert_refused(self.create(), "contains a signature: LVM2_member")

    def test_create_refuses_store_with_data(self):
        self.fresh()
        (self.store / "acme" / "index").write_bytes(b"x")
        self.assert_refused(self.create(), "the store is not empty")

    def test_create_refuses_existing_array_and_metadata(self):
        self.assert_refused(self.create(disks=["WD-WX12D3456706", "S7DNNJ0W100001X", "S7DNNJ0W100002Y", "ZFL1A2B3"]),
                            "a data array exists already")
        self.fresh()
        self.assert_refused(self.create(role="metadata", level="raid1", disks=["S7DNNJ0W100001X", "S7DNNJ0W100002Y"]),
                            "metadata tier is a follow-up")
        self.assert_refused(self.create(disks=self.HDDS[:3]), "raid6 needs at least 4 disks")
        self.assert_refused(self.create(disks=["NOPE", *self.HDDS[1:]]), "no disk with serial NOPE")

    # ------------------------------------------------------------ spare, replace, grow

    def test_add_spare(self):
        rid = self.req(op="add_spare", array=DATA_UUID, disk="WD-WX12D3456706")
        ops = self.tick()
        self.assertEqual(ops[rid]["state"], "done", ops[rid])
        self.assertIn(f"mdadm --manage {self.dev}/md126 --add /dev/sdh", self.calls())

    def test_spare_refused_on_system_array_and_small_disk(self):
        rid = self.req(op="add_spare", array=SYS_UUID, disk="WD-WX12D3456706")
        self.assert_refused(rid, "not a NexusBackup data or metadata array")
        rid = self.req(op="add_spare", array=DATA_UUID, disk="S7DNNJ0W100001X")
        self.assert_refused(rid, "smaller than the array members")
        rid = self.req(op="add_spare", array=DATA_UUID, disk="WD-WX12D3456701")
        self.assert_refused(rid, "is not empty: data")

    def test_replace_failed(self):
        rid = self.req(op="replace", array=DATA_UUID, disk="WD-WX12D3456706", failed="WD-WX12D3456704")
        ops = self.tick()
        self.assertEqual(ops[rid]["state"], "done", ops[rid])
        c = self.calls()
        self.assertLess(c.index(f"mdadm --manage {self.dev}/md126 --remove {self.dev}/sdf"),
                        c.index(f"mdadm --manage {self.dev}/md126 --add /dev/sdh"))

    def test_replace_any_failed_and_working_member(self):
        rid = self.req(op="replace", array=DATA_UUID, disk="WD-WX12D3456706", failed=None)
        self.assertEqual(self.tick()[rid]["state"], "done")
        self.assertIn(f"mdadm --manage {self.dev}/md126 --remove failed", self.calls())
        rid = self.req(op="replace", array=DATA_UUID, disk="WD-WX12D3456706", failed="WD-WX12D3456701")
        self.assertEqual(self.tick()[rid]["state"], "done")
        self.assertIn(f"mdadm --manage {self.dev}/md126 --replace {self.dev}/sdc --with /dev/sdh", self.calls())

    def clean(self):
        self.mdstat.write_text(MDSTAT_CLEAN)
        self.answers[f"mdadm --detail {self.dev}/md126"] = [0, DETAIL_CLEAN]
        j = json.loads(fixture("lsblk.json"))
        for n in j["blockdevices"]:
            if n["name"] == "sdg":
                n.update(fstype=None, uuid=None, label=None)
                n.pop("children")
        self.lsblk(json.dumps(j))

    def test_grow_refused_while_recovering_or_raid1(self):
        rid = self.req(op="grow", array=DATA_UUID, disk="WD-WX12D3456706")
        self.assert_refused(rid, "grow only a clean array")

    def since0(self):
        st = json.loads((self.dir / "state.json").read_text())
        for g in st["growfs"].values():
            g["since"] = 0
        (self.dir / "state.json").write_text(json.dumps(st))

    def test_grow_then_growfs(self):
        self.clean()
        rid = self.req(op="grow", array=DATA_UUID, disk="WD-WX12D3456706")
        ops = self.tick()
        self.assertEqual(ops[rid]["state"], "done", ops[rid])
        md = f"{self.dev}/md126"
        self.assertEqual([x for x in self.calls() if x.startswith("mdadm --manage") or x.startswith("mdadm --grow")],
                         [f"mdadm --manage {md} --add /dev/sdh", f"mdadm --grow {md} --bitmap=none",
                          f"mdadm --grow {md} --raid-devices=5"])
        self.assertFalse(any(c.startswith("xfs_growfs") for c in self.calls()))  # not in the same tick
        # still reshaping on the next tick: waits
        self.since0()
        self.mdstat.write_text(MDSTAT_CLEAN.replace("      bitmap: 2/30", "      [=>...]  reshape = 5.0% (1/2) finish=900.0min speed=1000K/sec\n      bitmap: 2/30"))
        self.tick()
        self.assertFalse(any(c.startswith("xfs_growfs") for c in self.calls()))
        self.assertIn(DATA_UUID, json.loads((self.dir / "state.json").read_text())["growfs"])
        # finished: the bitmap comes back, XFS grows
        self.mdstat.write_text(MDSTAT_CLEAN)
        ops = self.tick()
        self.assertIn(f"mdadm --grow {md} --bitmap=internal", self.calls())
        self.assertIn(f"xfs_growfs {self.store}", self.calls())
        self.assertEqual(ops[rid + "-fs"]["state"], "done")
        self.assertEqual(json.loads((self.dir / "state.json").read_text()), {"growfs": {}})


if __name__ == "__main__":
    unittest.main()
