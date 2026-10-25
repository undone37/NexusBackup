#!/usr/bin/env python3
"""Moves a VM to another ESXi host under the lab vCenter, with its disks (no shared storage in the lab, no
vMotion network: shut down, relocated, started again), for vmware-e2e.sh move (#37). Runs in the lab venv with pyvmomi
(~/nexus-lab/esxi/venv); the SSO password comes on stdin.

  vc_move.py where VM           the VM's host and datastore, as JSON
  vc_move.py move VM HOST [DS]  to host HOST (its address as vCenter knows it) and datastore DS (default: that
                                host's largest local datastore); prints the new place as JSON

env: VC (vCenter address)
"""
import json
import os
import ssl
import sys
import time

from pyVim.connect import Disconnect, SmartConnect
from pyVim.task import WaitForTask
from pyVmomi import vim


def find(content, kind, name):
    view = content.viewManager.CreateContainerView(content.rootFolder, [kind], True)
    try:
        return next(o for o in view.view if o.name == name)
    except StopIteration:
        sys.exit(f"no {kind.__name__} {name}")
    finally:
        view.Destroy()


def detach_media(vm):
    """CD-ROM and floppy to empty client devices: an ISO on a host's local datastore or a host floppy device
    keeps vCenter from moving the VM (CannotAccessVmDevice, lab: nx-cbt's install ISO)."""
    changes = []
    for d in vm.config.hardware.device:
        if isinstance(d, vim.vm.device.VirtualCdrom) and not isinstance(
                d.backing, vim.vm.device.VirtualCdrom.RemotePassthroughBackingInfo):
            d.backing = vim.vm.device.VirtualCdrom.RemotePassthroughBackingInfo(deviceName="", exclusive=False)
        elif isinstance(d, vim.vm.device.VirtualFloppy) and not isinstance(
                d.backing, vim.vm.device.VirtualFloppy.RemoteDeviceBackingInfo):
            d.backing = vim.vm.device.VirtualFloppy.RemoteDeviceBackingInfo(deviceName="")
        else:
            continue
        d.connectable = vim.vm.device.VirtualDevice.ConnectInfo(startConnected=False, connected=False,
                                                                 allowGuestControl=True)
        changes.append(vim.vm.device.VirtualDeviceSpec(operation="edit", device=d))
    if not changes:
        return
    task = vm.ReconfigVM_Task(spec=vim.vm.ConfigSpec(deviceChange=changes))
    while task.info.state in (vim.TaskInfo.State.queued, vim.TaskInfo.State.running):
        # a running guest that locked the CD-ROM door: vSphere asks whether to disconnect anyway; yes
        q = vm.runtime.question
        if q is not None:
            yes = next((c.key for c in q.choice.choiceInfo if c.label.lower() in ("yes", "ja")), q.choice.choiceInfo[0].key)
            vm.AnswerVM(q.id, yes)
        time.sleep(1)
    if task.info.state != vim.TaskInfo.State.success:
        sys.exit(f"reconfigure: {task.info.error}")


def power_off(vm):
    """A clean guest shutdown through VMware Tools (2 minutes), else a hard power-off."""
    try:
        vm.ShutdownGuest()
        for _ in range(120):
            if vm.runtime.powerState == vim.VirtualMachine.PowerState.poweredOff:
                return
            time.sleep(1)
    except vim.fault.ToolsUnavailable:
        pass
    WaitForTask(vm.PowerOffVM_Task())


def where(vm):
    return {"host": vm.runtime.host.name, "datastores": sorted(d.name for d in vm.datastore)}


def main(argv):
    if len(argv) < 3 or argv[1] not in ("where", "move") or (argv[1] == "move" and len(argv) not in (4, 5)):
        sys.exit(__doc__)
    # ponytail: the lab vCenter by IP on the lab network; certificate checks are the connector tests' job
    si = SmartConnect(host=os.environ["VC"], user="administrator@vsphere.local", pwd=sys.stdin.readline().strip(),
                      sslContext=ssl._create_unverified_context())
    try:
        content = si.RetrieveContent()
        vm = find(content, vim.VirtualMachine, argv[2])
        if argv[1] == "move":
            detach_media(vm)
            host = find(content, vim.HostSystem, argv[3])
            if len(argv) == 5:
                ds = next((d for d in host.datastore if d.name == argv[4]), None) or sys.exit(f"no datastore {argv[4]}")
            else:
                local = [d for d in host.datastore if d.summary.accessible and not d.summary.multipleHostAccess]
                ds = max(local or host.datastore, key=lambda d: d.summary.freeSpace)
            spec = vim.vm.RelocateSpec(host=host, datastore=ds, pool=host.parent.resourcePool)
            # ponytail: a cold migration (the lab hosts have no vMotion network); live vMotion when they get one
            was_on = vm.runtime.powerState == vim.VirtualMachine.PowerState.poweredOn
            if was_on:
                power_off(vm)
            WaitForTask(vm.RelocateVM_Task(spec=spec, priority=vim.VirtualMachine.MovePriority.highPriority))
            if was_on:
                WaitForTask(vm.PowerOnVM_Task())
        print(json.dumps(where(vm)))
    finally:
        Disconnect(si)


if __name__ == "__main__":
    main(sys.argv)
