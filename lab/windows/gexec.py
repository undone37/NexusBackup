#!/usr/bin/env python3
r"""Run PowerShell in a lab VM through the PVE guest agent (no guest password needed).

  gexec.py VMID 'powershell script'     prints stdout/stderr, exits with the script's exit code
  gexec.py VMID --put LOCAL 'C:\path'   copies a file in (guest-agent file-write, 45 KiB chunks)
Env: PVE_LAB_URL, PVE_LAB_TOKEN (user@realm!id=secret), PVE_NODE (pve-test), GEXEC_TIMEOUT (600 s).
Defaults are read from ~/nexus-lab/pve-lab.env when the variables are unset.
"""
import base64, json, os, ssl, sys, time, urllib.request

def env():
    p = os.path.expanduser("~/nexus-lab/pve-lab.env")
    if os.path.exists(p):
        for line in open(p):
            k, _, v = line.strip().partition("=")
            if k and k not in os.environ:
                os.environ[k] = v.strip("'\"")

def api(method, path, body=None):
    url = f"{os.environ['PVE_LAB_URL']}/api2/json{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"PVEAPIToken={os.environ['PVE_LAB_TOKEN']}", "Content-Type": "application/json"})
    # ponytail: lab host has a self-signed cert; pin it if this ever leaves the lab
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(req, context=ctx, timeout=60) as r:
        return json.loads(r.read().decode(errors="replace"), strict=False)["data"]

def put(base, vmid, local, dest):
    data = open(local, "rb").read()
    n = 45 * 1024
    parts = []
    for i in range(0, len(data), n):
        part = f"{dest}.part{i // n:05d}"
        api("POST", f"{base}/file-write", {"file": part, "content": base64.b64encode(data[i:i + n]).decode(), "encode": 0})
        parts.append(part)
    # ponytail: concatenation in PowerShell; one exec instead of a guest-side append API
    run(base, f"$o=[IO.File]::Create('{dest}'); foreach($p in @({','.join("'" + p + "'" for p in parts)}))"
        "{ $b=[IO.File]::ReadAllBytes($p); $o.Write($b,0,$b.Length); Remove-Item $p }; $o.Close();"
        f"(Get-FileHash '{dest}').Hash", check=True)

def run(base, script, check=False):
    pid = api("POST", f"{base}/exec", {"command": ["powershell", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-Command", "$ProgressPreference='SilentlyContinue'; " + script]})["pid"]
    end = time.time() + int(os.environ.get("GEXEC_TIMEOUT", "600"))
    while time.time() < end:
        s = api("GET", f"{base}/exec-status?pid={pid}")
        if s.get("exited"):
            sys.stdout.write(s.get("out-data", "").replace("\r", ""))
            sys.stderr.write(s.get("err-data", "").replace("\r", ""))
            if check and s.get("exitcode", 1):
                sys.exit(s.get("exitcode", 1))
            return s.get("exitcode", 1)
        time.sleep(2)
    sys.exit(f"gexec: timeout (pid {pid})")

def main():
    env()
    vmid = sys.argv[1]
    base = f"/nodes/{os.environ.get('PVE_NODE', 'pve-test')}/qemu/{vmid}/agent"
    if sys.argv[2] == "--put":
        put(base, vmid, sys.argv[3], sys.argv[4])
        return
    sys.exit(run(base, sys.argv[2]))

if __name__ == "__main__":
    main()
