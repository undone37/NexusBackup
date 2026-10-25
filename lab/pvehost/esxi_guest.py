#!/usr/bin/env python3
"""Runs a shell command in a lab VM through VMware Tools guest operations and prints its output (lab only: the
proxy's lab image, lab/proxy/Containerfile.lab, has a root password; the production proxy has no login).
Runs in the lab venv with pyvmomi (~/nexus-lab/esxi/venv); stdin: the SSO password, then the guest's root password.

  esxi_guest.py VM 'COMMAND'

env: VC (vCenter address)
"""
import os
import ssl
import sys
import time
import urllib.request

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim


def main(argv):
    if len(argv) != 3:
        sys.exit(__doc__)
    sso, root = sys.stdin.readline().strip(), sys.stdin.readline().strip()
    ctx = ssl._create_unverified_context()  # lab vCenter by address
    si = SmartConnect(host=os.environ["VC"], user="administrator@vsphere.local", pwd=sso, sslContext=ctx)
    try:
        content = si.RetrieveContent()
        view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
        vm = next((v for v in view.view if v.name == argv[1]), None) or sys.exit(f"no VM {argv[1]}")
        gom = content.guestOperationsManager
        auth = vim.vm.guest.NamePasswordAuthentication(username="root", password=root)
        out = f"/tmp/esxi-guest-{os.getpid()}.out"
        spec = vim.vm.guest.ProcessManager.ProgramSpec(programPath="/bin/sh", arguments=f"-c '{{ {argv[2]} ; }} > {out} 2>&1'")
        pid = gom.processManager.StartProgramInGuest(vm, auth, spec)
        for _ in range(600):
            p = gom.processManager.ListProcessesInGuest(vm, auth, [pid])[0]
            if p.endTime:
                break
            time.sleep(1)
        info = gom.fileManager.InitiateFileTransferFromGuest(vm, auth, out)
        sys.stdout.write(urllib.request.urlopen(info.url, context=ctx).read().decode(errors="replace"))
        gom.fileManager.DeleteFileInGuest(vm, auth, out)
        sys.exit(p.exitCode or 0)
    finally:
        Disconnect(si)


if __name__ == "__main__":
    main(sys.argv)
