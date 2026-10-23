"""NexusBackup for PegaProx (NexusBackup plan.md Phase 43): backup state per guest, "Back up now".

Routes (behind PegaProx's login, permission `plugins.view`; the checks below come on top):
  GET  /api/plugins/nexusbackup/api/ui              the page (PegaProx shows it as the plugin's tab)
  GET  /api/plugins/nexusbackup/api/clusters        PegaProx clusters this user may see that have a NexusBackup mapping
  GET  /api/plugins/nexusbackup/api/vms?cluster=ID  the guests of a cluster with their NexusBackup state
  POST /api/plugins/nexusbackup/api/backup          {"cluster": ID, "vmid": N}: start a backup of that guest

Seeing the state needs PegaProx's `backup.view` on the cluster, starting a backup `backup.create` (or
`vm.backup`) and `allow_backup` in config.json. NexusBackup itself only takes what the API token allows:
`read`, or `backup` (read and start backups, nothing else). config.json is edited in PegaProx's plugin
settings (`plugins.manage`); see config.json.example.
"""
import json
import logging
import os
import time

from flask import Response, request

from pegaprox.api.plugins import register_plugin_route
from pegaprox.globals import cluster_managers

from . import core

PLUGIN_ID = "nexusbackup"
PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
_cache = {}


def _config():
    try:
        with open(os.path.join(PLUGIN_DIR, "config.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _user():
    from pegaprox.utils.auth import build_authz_user

    return build_authz_user(request.session.get("user", ""), request.session)


def _may(user, perm, cluster):
    from pegaprox.utils.rbac import get_user_clusters, has_permission

    allowed = get_user_clusters(user)
    return has_permission(user, perm) and (allowed is None or cluster in allowed)


def _mapping(cfg, cluster):
    """(Appliance, tenant, source_id or None) of a PegaProx cluster, from config.json."""
    for a in cfg.get("appliances", []):
        m = (a.get("clusters") or {}).get(cluster)
        if m:
            app = core.Appliance(a["url"], a["token"], a["cert_sha256"], timeout=a.get("timeout", 10))
            return app, m["tenant"], m.get("source_id")
    return None


def _clusters():
    cfg, user = _config(), _user()
    out = []
    for cid, mgr in cluster_managers.items():
        if _mapping(cfg, cid) and _may(user, "backup.view", cid):
            out.append({"id": cid, "name": getattr(mgr.config, "name", cid), "connected": mgr.is_connected})
    return {"clusters": out, "allow_backup": bool(cfg.get("allow_backup"))}


def _vms():
    cid = request.args.get("cluster", "")
    cfg = _config()
    if not _may(_user(), "backup.view", cid):
        return {"error": "no permission to see backups of this cluster"}, 403
    m = _mapping(cfg, cid)
    mgr = cluster_managers.get(cid)
    if not m or mgr is None:
        return {"error": "this cluster has no NexusBackup mapping in the plugin settings"}, 404
    app, tenant, source_id = m
    ttl = cfg.get("cache_seconds", 60)
    hit = _cache.get((cid, tenant))
    try:
        if hit and time.time() - hit[0] < ttl:
            st = hit[1]
        else:
            st = app.state(tenant)
            _cache[(cid, tenant)] = (time.time(), st)
        vms = [v for v in mgr.get_vm_resources() if v.get("type") in ("qemu", "lxc") and not v.get("template")]
    except RuntimeError as e:
        return {"error": str(e)}, 502
    rows = core.guest_rows(vms, tenant, st["groups"], st["policies"], st["snapshots"], st["tests"], st["alerts"],
                           int(time.time()), source_id)
    return {"cluster": cid, "tenant": tenant, "summary": core.summary(rows), "vms": rows}


def _backup():
    # PegaProx hands every method to the handler; only a POST (with its CSRF checks) starts anything
    if request.method != "POST":
        return {"error": "POST only"}, 405
    cfg = _config()
    body = request.get_json(silent=True) or {}
    cid, vmid = str(body.get("cluster", "")), body.get("vmid")
    user = _user()
    if not cfg.get("allow_backup"):
        return {"error": "starting backups is off in the plugin settings (allow_backup)"}, 403
    if not (_may(user, "backup.create", cid) or _may(user, "vm.backup", cid)):
        return {"error": "no permission to back up guests of this cluster"}, 403
    if not isinstance(vmid, int) or vmid <= 0:
        return {"error": "vmid: a number"}, 400
    m = _mapping(cfg, cid)
    if not m:
        return {"error": "this cluster has no NexusBackup mapping"}, 404
    app, tenant, source_id = m
    try:
        st = app.state(tenant)
        row = core.guest_rows([{"vmid": vmid}], tenant, st["groups"], st["policies"], [], [], [], 0, source_id)[0]
        if not row["group"]:
            return {"error": f"guest {vmid} is in no NexusBackup protection group"}, 409
        job = app.backup(tenant, row["group"]["id"], vmid)
    except RuntimeError as e:
        return {"error": str(e)}, 502
    _cache.pop((cid, tenant), None)
    try:
        from pegaprox.utils.audit import log_audit

        log_audit(request.session.get("user", "?"), "nexusbackup.backup",
                  f"NexusBackup backup of {vmid} on {cid}: job {job.get('id')}")
    except ImportError:  # older PegaProx: the NexusBackup audit log has the job (actor "<user> via token <name>")
        pass
    return {"job": job.get("id"), "tenant": tenant, "group": row["group"]["name"]}


def _ui():
    with open(os.path.join(PLUGIN_DIR, "ui.html"), encoding="utf-8") as f:
        return Response(f.read(), mimetype="text/html", headers={"Cache-Control": "no-store"})


def register(app):
    register_plugin_route(PLUGIN_ID, "ui", _ui)
    register_plugin_route(PLUGIN_ID, "clusters", _clusters)
    register_plugin_route(PLUGIN_ID, "vms", _vms)
    register_plugin_route(PLUGIN_ID, "backup", _backup)
    logging.info("[PLUGINS] NexusBackup plugin registered")
