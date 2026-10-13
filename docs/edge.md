# Edge proxy for roaming agents (Phase 26)

Status: implemented 2026-10-13 (crate `crates/edge`, binary `nexus-edge`; agent side in `agent-core`; appliance side
in `agent-conn`, scheduler and web-api; OS image `os/edge/`). Tested in-process (relay pairing, end to end with a real
agent and `agent-conn` through a real edge, rate limits, unknown certificates, payload only as TLS records). **Not yet
run as a VM** (lab: `lab/edge/e2e.sh`); the edge image is not built in CI yet.

User decisions (plan.md §2 "Edge proxy (Phase 26)", §15 "Phase 26"): a separate single bootc VM hosted by the
customer in a DMZ or the client network, internet-facing and hardened; the appliance connects **out** to it and
manages it; laptops connect **out** to it with their agent certificate; the backup/restore session stays TLS end to
end between appliance and agent; "back up now" from the endpoint starts within seconds from anywhere; a compromised
edge means denial of service and connection metadata, no data and no path to the appliance.

## Picture

```
 laptop (anywhere)                      edge VM (DMZ)                         appliance (LAN)
 nexus-agent ──TLS(agent cert)──► 443  nexus-edge  7445 ◄──TLS(appliance cert)── nexus-agentctl
   rendezvous (long-lived) ─────────►  pairs streams  ◄─────── control link (scheduler: edge-link)
   stream for nonce N ──────────────►  relays bytes   ◄─────── Open{agent} (one per session)
        └────────────── inner TLS 1.3 session: appliance (client) ⇄ agent (server), pinned ──────────────┘
```

- **Public port 443** (agents): TLS 1.3, ALPN `nexus-edge/1`, the edge's own self-signed certificate (ECDSA P-256,
  created by `nexus-edge init`, pinned by SHA-256 on both the appliance and the agents). **The client certificate is
  mandatory** and checked in the handshake: it must chain to the appliance agent CA that the appliance pushed, carry
  `CN=nexus-agent:<id>`, and its fingerprint must be one of the pins pushed for that agent. Before the appliance
  pushed its configuration every handshake fails. Nothing is parsed before the handshake.
- **Control port 7445** (appliance only): TLS 1.3, client certificate mandatory: before enrollment any certificate
  (the token proofs follow), afterwards only the pinned appliance client certificate. The edge never connects to the
  appliance; the appliance's link is outbound for the appliance (one firewall egress rule per edge).
- **Relay.** For each session the appliance opens a new control connection with `Open { agent }`. The edge sends
  `Connect { nonce }` over the agent's rendezvous connection; the agent opens a new connection `Stream { nonce }`;
  the edge pairs them and copies bytes in both directions. Inside, the appliance runs its normal mTLS client and the
  agent its normal TLS server (the same code as on port 7444): the edge forwards TLS records it cannot decrypt.
- **Wake.** A local "back up now" request makes the agent open a short `Wake` connection; the edge answers the
  appliance's pending long poll (`Wait`) at once; the scheduler polls the agent through the edge immediately; the
  poll collects the request (protocol v1.4) and queues the backup, which runs through the edge.
- **Routes.** Agents with an edge are tried directly first (3 s connect timeout), then through the edge; the job log
  (`agent-info … "via"`) and the agent list (`via`) show which route was used. Agents keep listening on 7444 as well.

Protocol details (messages, framing, proofs, limits): docs/agent-protocol.md "v1.7 — edge proxy".

## Lifecycle

1. **Create** (Settings → **Edges** → **Add edge**, admin): name, control address as the appliance reaches it
   (`host`, port 7445), public address as laptops reach it (`public_host`, port 443). The appliance shows a one-time
   token (24 h; only its digest is stored, sealed to the scheduler) and the console command.
2. **Install** the edge VM from the edge image (qcow2 or ISO, `os/edge/build.sh`), 1 vCPU / 1 GiB / 8 GiB is plenty.
   On its console (tty1, `nexus-edge-setup`): network (nmtui), then the token (`nexus-edge init --token -`); the
   console shows the edge certificate fingerprint.
3. **Connect** (admin): job `edge_enroll` — both sides prove the token bound to this TLS session (a man in the middle
   cannot relay the proofs), the edge pins the appliance client certificate, the appliance pins the edge
   certificate (compare it with the console). The token is consumed on both sides.
4. **Link.** The scheduler keeps one `nexus-agentctl edge-link` process per enrolled edge (restarted 15 s after it ends, and
   when the configuration changes): it pushes the CA certificate and the pins of the agents assigned to the edge,
   pushes an update when the appliance carries a newer signed `nexus-edge`, and long-polls for health, wakes and log
   lines. **Online** = health within 120 s.
5. **Assign laptops** (Agents → **Endpoint settings** → **Reach via edge**, admin). The next poll on the direct path
   sends `SetEdge` (protocol v1.7) to the agent, which then keeps its rendezvous connection. Agents without the
   capability (older versions) can be configured with `edge` / `edge_sha256` in `agent.conf`.
6. **Remove**: deleting the edge on the appliance clears the assignment of its agents (they are told at the next
   direct poll); re-enrolling needs a new token and `nexus-edge init` on the console.

## Updates

- **nexus-edge binary**: pushed by the appliance over the control link (`Update`), only if the appliance's
  `/usr/share/nexus/edge/nexus-edge.version` is newer. The edge checks the cosign blob signature against the release
  keys baked into its image (`/usr/share/nexus-edge/release-keys`, the same keys as agent self-update) and the embedded
  version, stores it in `/var/lib/nexus-edge/update/` and exits; systemd restarts it, and at start nexus-edge
  re-verifies the stored binary before it execs it (a file swapped on disk is refused).
  **Open:** the appliance image does not carry `/usr/share/nexus/edge/` yet (like `/usr/share/nexus/agent`, the
  signed binaries come from the release page; the lab puts them there).
- **Edge OS**: the edge has no outbound HTTPS (no registry pulls); OS updates are a new edge image
  (`bootc switch` from a reachable registry in a maintenance window, or reinstall from the release's image and
  re-enroll). **Open:** OS updates driven by the appliance.

## Hardening of the edge image (`os/edge/`)

- bootc image (same AlmaLinux base as the appliance) with only nexus-edge, nftables, chrony and nmtui; no SSH, no web
  UI, root locked, every getty masked (tty1 runs only the fixed setup menu), no rescue target, `rd.shell=0`.
- nftables: input only 443 and 7445 (control port optionally limited to the appliance's address from the console
  menu), SYN meter per source; output only DNS, NTP/NTS and DHCP.
- `nexus-edge.service`: user `nexus-edge`, only `CAP_NET_BIND_SERVICE`, `SocketBindAllow` 443/7445, the usual
  systemd sandbox (ProtectSystem=strict, MemoryDenyWriteExecute, system call filter).
- SELinux domain `nexus_edge_t` (module `os/edge/selinux/nexus_edge.te`): binds 443 (`http_port_t`) and 7445
  (`nexus_edge_control_port_t`), manages only `/var/lib/nexus-edge`, reads the release keys; no `name_connect` rule.
- Rate limits (pushed by the appliance, defaults): 60 new connections per minute per source IP (burst 20), 120 per
  minute per agent certificate, 1024 connections, 10 s handshake timeout; control port 30 per minute per IP. Frames
  ≤ 64 KiB on the public port.

## What the edge sees and stores

- Stores: its TLS key and certificate, the token digest until enrollment, the appliance certificate fingerprint, the
  pushed CA certificate and agent pin list, verified updates.
- Sees: which agent (id from the certificate) connects from which IP address and when, session start/end and byte
  counts, sizes and timing of TLS records. It logs connection metadata only (to the journal and to the appliance's
  edge log), never payload.
- Never sees: backup data, file names, chunk hashes, tenant keys, the appliance CA key or any agent key.

## Threat model (docs/threat-model.md T53–T55)

| | Threat | Outcome |
|---|---|---|
| T53 | Edge compromised (root on the VM) | DoS + metadata. No data (inner TLS end to end, no keys on the edge), cannot impersonate appliance or agent (pinned certificates on both ends), no path to the appliance (it only dials out and speaks a fixed message set). |
| T53 | Leaked edge token, console access to the edge (rogue enrollment) | Token proofs bound to the TLS session, one-time, 24 h; a rogue "appliance" paired with the edge cannot authenticate to agents; console re-init = DoS until re-enrolled. |
| T54 | Internet scanning / flooding of 443 | mTLS before any parsing, unknown certificates fail the handshake; per-IP and per-certificate limits; only two ports; DoS of the edge path remains possible. |
| T55 | Stolen laptop certificate used at the edge | Same power as the stolen key had before (pose as that agent); revoking the agent or its edge assignment removes the pin at the next config push. |

## Open

- VM lab run (`lab/edge/e2e.sh all`): SELinux in enforcing, `systemd-analyze security`, the real rendezvous from a
  lab VM, "back up now" latency, update push. An external port scan needs a second network.
- CI build of the edge image (qcow2/ISO) and of the signed `nexus-edge` release blob; shipping it in the appliance
  image's `/usr/share/nexus/edge`.
- Edge OS updates driven by the appliance; high availability (one edge per appliance group; a second edge can be
  added and laptops split between them, no automatic failover).
