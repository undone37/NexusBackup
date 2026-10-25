#!/usr/bin/env python3
"""Deploys the hot-add proxy OVA (os/proxy/build.sh --ova, #35) through the lab vCenter, as "Deploy OVF Template"
does: the OVF manager builds the import spec with the property nexus.token, an NFC lease takes the disk upload,
the VM is powered on and its address (VMware Tools) printed. Runs in the lab venv with pyvmomi
(~/nexus-lab/esxi/venv); the SSO password comes on stdin.

  esxi_ova.py deploy OVA NAME HOST DATASTORE TOKEN   import as VM NAME on HOST (its address in vCenter)
  esxi_ova.py destroy NAME                           power off and delete VM NAME (lab VMs only: names nx-ova-*)

env: VC (vCenter address); NEXUS_IP (CIDR), NEXUS_GATEWAY, NEXUS_DNS: the network properties (empty: DHCP)
"""
import json
import os
import ssl
import sys
import tarfile
import time
import urllib.request

from pyVim.connect import Disconnect, SmartConnect
from pyVim.task import WaitForTask
from pyVmomi import vim


def find(content, kind, name):
    view = content.viewManager.CreateContainerView(content.rootFolder, [kind], True)
    try:
        return next((o for o in view.view if o.name == name), None)
    finally:
        view.Destroy()


def deploy(si, ova, name, host_name, ds_name, token):
    content = si.RetrieveContent()
    host = find(content, vim.HostSystem, host_name) or sys.exit(f"no host {host_name}")
    ds = next((d for d in host.datastore if d.name == ds_name), None) or sys.exit(f"no datastore {ds_name}")
    net = next((n for n in host.network if n.name == "VM Network"), None) or sys.exit("no network VM Network")
    dc = host.parent
    while not isinstance(dc, vim.Datacenter):
        dc = dc.parent
    with tarfile.open(ova) as t:
        ovf = t.extractfile(next(m for m in t.getmembers() if m.name.endswith(".ovf"))).read().decode()
        params = vim.OvfManager.CreateImportSpecParams(
            entityName=name,
            diskProvisioning="thin",
            propertyMapping=[vim.KeyValue(key="nexus.token", value=token)] + [
                vim.KeyValue(key=f"nexus.{k}", value=os.environ[f"NEXUS_{k.upper()}"])
                for k in ("ip", "gateway", "dns") if os.environ.get(f"NEXUS_{k.upper()}")
            ],
            networkMapping=[vim.OvfManager.NetworkMapping(name="VM Network", network=net)],
        )
        spec = content.ovfManager.CreateImportSpec(ovf, host.parent.resourcePool, ds, params)
        if spec.error:
            sys.exit("import spec: " + "; ".join(e.msg for e in spec.error))
        lease = host.parent.resourcePool.ImportVApp(spec.importSpec, dc.vmFolder, host)
        while lease.state == vim.HttpNfcLease.State.initializing:
            time.sleep(1)
        if lease.state != vim.HttpNfcLease.State.ready:
            sys.exit(f"lease: {lease.state} {lease.error}")
        ctx = ssl._create_unverified_context()  # lab: the host's NFC certificate is the lab ESXi's
        files = {f.deviceId: f.path for f in spec.fileItem}
        # only the disks: the lease also offers an nvram upload (EFI firmware) the OVA has no file for
        for du in (d for d in lease.info.deviceUrl if d.disk and d.importKey in files):
            member = t.getmember(files[du.importKey])
            url = du.url.replace("*", host_name)
            req = urllib.request.Request(url, data=t.extractfile(member), method="POST", headers={
                "Content-Type": "application/x-vnd.vmware-streamVmdk",
                "Content-Length": str(member.size),
                "Cookie": si._stub.cookie,
            })
            urllib.request.urlopen(req, context=ctx, timeout=3600).read()
        lease.HttpNfcLeaseProgress(100)
        lease.HttpNfcLeaseComplete()
    vm = find(content, vim.VirtualMachine, name) or sys.exit(f"{name} not created")
    WaitForTask(vm.PowerOnVM_Task())
    for _ in range(120):
        ip = vm.guest.ipAddress
        if ip and ":" not in ip:
            print(json.dumps({"vm": name, "ip": ip, "uuid": vm.config.uuid}))
            return
        time.sleep(5)
    sys.exit(f"{name}: no address from VMware Tools after 10 minutes")


def destroy(si, name):
    if not name.startswith("nx-ova-"):
        sys.exit("only lab VMs named nx-ova-* are destroyed")
    vm = find(si.RetrieveContent(), vim.VirtualMachine, name)
    if vm is None:
        return
    if vm.runtime.powerState == vim.VirtualMachine.PowerState.poweredOn:
        WaitForTask(vm.PowerOffVM_Task())
    WaitForTask(vm.Destroy_Task())


def main(argv):
    if not ((len(argv) == 7 and argv[1] == "deploy") or (len(argv) == 3 and argv[1] == "destroy")):
        sys.exit(__doc__)
    si = SmartConnect(host=os.environ["VC"], user="administrator@vsphere.local", pwd=sys.stdin.readline().strip(),
                      sslContext=ssl._create_unverified_context())
    try:
        if argv[1] == "deploy":
            deploy(si, *argv[2:])
        else:
            destroy(si, argv[2])
    finally:
        Disconnect(si)


if __name__ == "__main__":
    main(sys.argv)
