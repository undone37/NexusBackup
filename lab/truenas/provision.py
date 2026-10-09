#!/usr/bin/env python3
"""Provision the TrueNAS lab VM over the JSON-RPC API (idempotent).

  provision.py

- truenas_admin: lab SSH key ($LAB/truenas/admin_ed25519), passwordless sudo (lab only), SSH service on
- pool `tank` (mirror of the two 8 GB disks); datasets tank/home, tank/data (POSIX ACLs),
  tank/data/projects (child), tank/smb (SMB preset: NFSv4 ACLs), tank/other (never selected)
- the appliance account as documented in docs/truenas-connector.md "TrueNAS setup":
  group + user `nexusbackup` (home tank/home/nexusbackup, bash, password disabled, no SMB,
  sudo without password for find/tar/realpath/zfs only), privilege `NexusBackup` with roles
  SNAPSHOT_WRITE + SNAPSHOT_DELETE + DATASET_READ for that group, an API key of the user
  ($LAB/truenas/api-key, 0600); the user's authorized_keys line comes from
  $LAB/truenas/authorized_keys if present (written by `nexus-truenas … authorized-key`)
- API certificate -> $LAB/truenas/cert.pem, SSH host key -> $LAB/truenas/known_hosts
"""
import asyncio
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tn  # noqa: E402

LAB = tn.LAB
D = f"{LAB}/truenas"
SUDO = ["/usr/bin/find", "/usr/bin/tar", "/usr/bin/realpath", "/usr/sbin/zfs"]
ROLES = ["SNAPSHOT_WRITE", "SNAPSHOT_DELETE", "DATASET_READ"]


def write600(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, data.encode())
    os.close(fd)


async def main():
    if not os.path.exists(f"{D}/admin_ed25519"):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "truenas-lab-admin",
                        "-f", f"{D}/admin_ed25519"], check=True)
    ws, rpc = await tn.connect()
    async with ws:
        admin = (await rpc.call("user.query", [["username", "=", "truenas_admin"]]))[0]
        await rpc.call("user.update", admin["id"], {
            "sshpubkey": open(f"{D}/admin_ed25519.pub").read().strip(),
            "sudo_commands_nopasswd": ["ALL"],
        })
        await rpc.call("ssh.update", {"tcpport": 22})
        await rpc.call("service.update", "ssh", {"enable": True})
        await rpc.job("service.control", "START", "ssh")
        print("ssh on", flush=True)

        if not await rpc.call("pool.query", [["name", "=", "tank"]]):
            disks = sorted(d["name"] for d in await rpc.call("disk.get_unused"))
            print("creating pool tank on", disks, flush=True)
            await rpc.job("pool.create", {"name": "tank", "topology": {"data": [{"type": "MIRROR", "disks": disks}]}})
        for ds, extra in [("tank/home", {}), ("tank/data", {"acltype": "POSIX", "aclmode": "DISCARD"}),
                          ("tank/data/projects", {}), ("tank/smb", {"share_type": "SMB"}), ("tank/other", {})]:
            if not await rpc.call("pool.dataset.query", [["id", "=", ds]]):
                await rpc.call("pool.dataset.create", {"name": ds, **extra})
                print("dataset", ds, flush=True)

        if not await rpc.call("group.query", [["group", "=", "nexusbackup"]]):
            await rpc.call("group.create", {"name": "nexusbackup", "smb": False})
        grp = (await rpc.call("group.query", [["group", "=", "nexusbackup"]]))[0]
        want = {
            "full_name": "NexusBackup appliance",
            "shell": "/usr/bin/bash",
            "password_disabled": True,
            "smb": False,
            "sudo_commands_nopasswd": SUDO,
        }
        ak = f"{D}/authorized_keys"
        if os.path.exists(ak):
            want["sshpubkey"] = open(ak).read().strip()
        users = await rpc.call("user.query", [["username", "=", "nexusbackup"]])
        if not users:
            await rpc.call("user.create", {"username": "nexusbackup", "group": grp["id"], "group_create": False,
                                           "home": "/mnt/tank/home", "home_create": True, "home_mode": "700", **want})
            users = await rpc.call("user.query", [["username", "=", "nexusbackup"]])
            print("user nexusbackup", flush=True)
        else:
            await rpc.call("user.update", users[0]["id"], want)
        if not await rpc.call("privilege.query", [["name", "=", "NexusBackup"]]):
            await rpc.call("privilege.create", {"name": "NexusBackup", "local_groups": [grp["gid"]], "ds_groups": [],
                                                "roles": ROLES, "web_shell": False})
            print("privilege NexusBackup", flush=True)
        if not os.path.exists(f"{D}/api-key"):
            for k in await rpc.call("api_key.query", [["name", "=", "nexus-appliance"]]):
                await rpc.call("api_key.delete", k["id"])
            k = await rpc.call("api_key.create", {"name": "nexus-appliance", "username": "nexusbackup"})
            write600(f"{D}/api-key", k["key"] + "\n")
            print("api key created", flush=True)
    write600(f"{D}/cert.pem", tn.cert_pem())
    kh = subprocess.run(["ssh-keyscan", "-p", "12222", "-t", "ed25519", "127.0.0.1"], capture_output=True, text=True)
    write600(f"{D}/known_hosts", kh.stdout)
    print("provisioned", flush=True)


asyncio.run(main())
