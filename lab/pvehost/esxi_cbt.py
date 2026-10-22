#!/usr/bin/env python3
"""Control side of the CBT spike (docs/vmware-transport-spike.md, option A): snapshots and
QueryChangedDiskAreas on the nested ESXi of esxi.sh. Runs in the lab venv with pyvmomi
(~/nexus-lab/esxi/venv); the data reads run on the appliance (cbt_read.py).

  esxi_cbt.py snap NAME [SINCE]   snapshot NAME of nx-cbt; prints JSON: the disk's changeId, capacity,
                                  datastore path of the base disk and the extents changed since the
                                  changeId SINCE ("*": every allocated extent); with SINCE also every
                                  allocated extent ("allocated", for the check against a full read)
  esxi_cbt.py remove NAME         remove snapshot NAME (consolidates into the base disk)
  esxi_cbt.py attach PROXY NAME   hot-add: the base disk of snapshot NAME to VM PROXY as SCSI 0:1,
                                  independent-nonpersistent (the proxy's writes go to a redo log)
  esxi_cbt.py detach PROXY        remove that disk from PROXY again (the disk file is kept)

env: LAB (~/nexus-lab/esxi: ip, root.password), VM (nx-cbt)
"""
import json
import os
import ssl
import sys

from pyVim.connect import Disconnect, SmartConnect
from pyVim.task import WaitForTask
from pyVmomi import vim

LAB = os.environ.get("LAB", os.path.expanduser("~/nexus-lab/esxi"))
VM = os.environ.get("VM", "nx-cbt")


def read(name):
    with open(os.path.join(LAB, name)) as f:
        return f.read().strip()


def find_vm(si, name=None):
    view = si.content.viewManager.CreateContainerView(si.content.rootFolder, [vim.VirtualMachine], True)
    try:
        return next(v for v in view.view if v.name == (name or VM))
    except StopIteration:
        sys.exit(f"no VM {name or VM}")


def find_snap(tree, name):
    for s in tree or []:
        if s.name == name:
            return s.snapshot
        hit = find_snap(s.childSnapshotList, name)
        if hit:
            return hit
    return None


def disk_of(config):
    return next(d for d in config.hardware.device if isinstance(d, vim.vm.device.VirtualDisk))


def changed(vm, snap, disk, since):
    """Every extent QueryChangedDiskAreas reports, merged into [offset, length] pairs."""
    out, off = [], 0
    while off < disk.capacityInBytes:
        r = vm.QueryChangedDiskAreas(snapshot=snap, deviceKey=disk.key, startOffset=off, changeId=since)
        for a in r.changedArea:
            if out and out[-1][0] + out[-1][1] == a.start:
                out[-1][1] += a.length
            else:
                out.append([a.start, a.length])
        nxt = r.startOffset + r.length
        if nxt <= off:
            break
        off = nxt
    return out


def hotadd(si, proxy, name):
    """Attaches (name given) or detaches the hot-added disk at SCSI 0:1 of VM `proxy`."""
    p = find_vm(si, proxy)
    ctl = next(d for d in p.config.hardware.device if isinstance(d, vim.vm.device.VirtualSCSIController))
    spec = vim.vm.device.VirtualDeviceSpec()
    if name is None:
        disk = next(
            (d for d in p.config.hardware.device if isinstance(d, vim.vm.device.VirtualDisk) and d.controllerKey == ctl.key and d.unitNumber == 1),
            None,
        )
        if disk is None:
            return
        # no fileOperation: the disk file belongs to the protected VM and stays
        spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
        spec.device = disk
    else:
        vm = find_vm(si)
        b = disk_of(find_snap(vm.snapshot.rootSnapshotList, name).config).backing
        while b.parent:
            b = b.parent
        disk = vim.vm.device.VirtualDisk()
        disk.controllerKey, disk.unitNumber, disk.key = ctl.key, 1, -1
        disk.backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo(fileName=b.fileName, diskMode="independent_nonpersistent")
        spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        spec.device = disk
    WaitForTask(p.ReconfigVM_Task(spec=vim.vm.ConfigSpec(deviceChange=[spec])))


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("snap", "remove", "attach", "detach"):
        sys.exit(__doc__)
    si = SmartConnect(host=read("ip"), user="root", pwd=read("root.password"), sslContext=ssl._create_unverified_context())
    try:
        if sys.argv[1] in ("attach", "detach"):
            return hotadd(si, sys.argv[2], sys.argv[3] if sys.argv[1] == "attach" else None)
        vm = find_vm(si)
        name = sys.argv[2]
        if sys.argv[1] == "remove":
            snap = find_snap(vm.snapshot and vm.snapshot.rootSnapshotList, name)
            if snap:
                WaitForTask(snap.RemoveSnapshot_Task(removeChildren=False))
            return
        WaitForTask(vm.CreateSnapshot_Task(name=name, description="nexus cbt spike", memory=False, quiesce=False))
        snap = find_snap(vm.snapshot.rootSnapshotList, name)
        disk = disk_of(snap.config)
        since = sys.argv[3] if len(sys.argv) > 3 else "*"
        # the snapshot's disk is a delta; its parent chain ends at the base flat file that the reads use
        b = disk.backing
        while b.parent:
            b = b.parent
        ext = changed(vm, snap, disk, since)
        print(
            json.dumps(
                {
                    "change_id": disk.backing.changeId,
                    "capacity": disk.capacityInBytes,
                    "base": b.fileName,
                    "extents": ext,
                    "bytes": sum(e[1] for e in ext),
                    "allocated": changed(vm, snap, disk, "*") if since != "*" else ext,
                }
            )
        )
    finally:
        Disconnect(si)


if __name__ == "__main__":
    main()
