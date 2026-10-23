# NFC protocol (vStorage APIs for Data Protection, network mode)

The NFC (Network File Copy) protocol is the data transport the vStorage APIs for Data Protection (VADP) use to
read a VM's virtual disks over the management network, without a proxy VM on the ESXi host. VMware does not publish
it; the only official client is the closed-source VDDK (`libvixDiskLib`). Since Broadcom restricted VDDK to
partners (2026-08), NexusBackup speaks NFC directly. `crates/vmware/src/nfc.rs` is a clean reimplementation from
the public protocol description of the open-source [OpenVixDiskLib](https://github.com/cloudbase/OpenVixDiskLib)
(LGPL) and our own lab observation against vCenter 8.0.3 / ESXi 8.0.3; it ships no VMware code or library.

This is interoperability with a documented data-protection API the operator is licensed to use. It reads only; it
never writes to a guest disk.

## Layers

```
 appliance ── TCP 902 ── ESXi NFC service (authd)
   1. authd: plaintext 220 banner, TLS (pinned to the ticket thumbprint), text commands
   2. classic NFC: 264-byte little-endian frames (handshake)
   3. AIO: 16-byte header (magic 0xA100DA7A) + payload; open session, open file, read
```

The ticket comes from SOAP first: `NfcGetVmFiles` on the `NfcService` (vCenter `nfcService`, host `ha-nfc`)
returns a `HostServiceTicket` with the NFC host, port 902, the ESXi certificate's SHA-1 thumbprint, the `PROXY`
service name (`vpxa-nfc`) and a one-time `sessionId`. See `crates/vmware/src/vsphere.rs::nfc_ticket`.

### 1. authd (TCP 902)

```
S -> 220 VMware Authentication Daemon Version 1.10: ... (plaintext, on connect)
[TLS handshake, client wraps the socket; certificate pinned to the ticket's SHA-1 thumbprint]
C -> SESSION <sessionId>        (no reply)
C -> BANNER
C -> THUMBPRINT_SHA2 PlainText
S -> 200 <SHA-256 thumbprint>   (220 info lines, if any, are skipped)
C -> PROXY vpxa-nfc
S -> 200 Connect ha-nfc
```

The 220 banner is sent in clear before TLS; sending commands before wrapping TLS closes the connection. For NBD
(`useSSL=0`) the NFC bytes then flow over the raw TCP connection; NBDSSL wraps a second TLS over the same socket
(not implemented: we read over NBD, the chunk store encrypts at rest).

### 2. classic NFC (264-byte frames, little-endian)

Offset 0 is a `uint32` message type; the body follows and the frame is zero-padded to 264 bytes.

| Type | Name | Body |
|---|---|---|
| 43 | HANDSHAKE | ASCII `PlainText` at offset 4 |
| 33 | SESSION_PARAMS | zeros |
| 36 | SESSION_PARAMS_REPLY | (reply) |
| 51 | VERSION | `uint32` version at offset 4 (11; server must be >= 3) |
| 54 | CONNECTION_DATA | `uint32` nameLen, `uint32` opIdLen; then the raw strings `vddk` and `nbdmode` (unframed) |
| 55 | SESSION_FEATURES | `uint32` 3 |
| 52 | AIO_SESSION_OPEN | zeros; the server echoes it |
| 4 | SESSION_COMPLETE | zeros, sent on close |

Sequence: `43`, `33` -> `36`; `51` -> `51`; `54` + `"vddk"` + `"nbdmode"`; `55`; `52` -> `52`.

### 3. AIO

16-byte header, four little-endian `uint32`: magic `0xA100DA7A`, type, payload size, opId (from 0, +1 per client
message, echoed by the server).

| Type | Name | Payload |
|---|---|---|
| 2 | OPEN_SESSION | `<IIII>` 0, buffer size (2 MiB), buffer count (1), 0 -> 16 zeros |
| 9 | SET_SOCK_OPTS | 12 zeros -> reply ignored |
| 22 | SET_RES_POOL | `<I>` 1 (no reply) |
| 4 | OPEN_FILE | 60 bytes: `<I>` pathLen, zeros, `<I>` NFC_DISK(2) at 16, `<I>` flags 0x1e (read-only) at 20; path follows unframed. Reply: handle `<Q>` at 8, sector size `<I>` at 36 |
| 7 | IO | 44 bytes: handle `<Q>`, opcode `<Q>` (low 32 = 1 read; high 32 = compression, 0 none), byte offset `<Q>`, length `<Q>`, length `<I>`, length `<I>`, 0 |
| 5 | CLOSE_FILE | `<Q>` handle |
| 3 | CLOSE_SESSION | `<I>` 0 |
| 1 | ERROR | error code |

#### Read (type 7)

One IO request per read. The server returns one or more fragments, each: a 16-byte header (type 7, same opId,
size 44), a 44-byte payload, then the data. Payload: opcode `<Q>` at 8 (high 32 = compression of this fragment),
request offset `<Q>` at 16, fragment offset `<I>` at 28 (byte position within the request), uncompressed length
`<I>` at 32, extra size `<I>` at 36 (bytes on the wire: for raw == uncompressed length). We request compression 0
(none): the extra is the raw data, placed at the fragment offset. Collect fragments until the lengths sum to the
request. The server splits replies to the OPEN_SESSION buffer size (2 MiB here).

## What we do not use

FastLZ compression (the chunk store compresses and deduplicates on its own), writes (read-only backup), NBDSSL,
disk geometry (`DDB_GET`), and the host-switch/interruption features. CBT (changed blocks) comes from the SOAP
`QueryChangedDiskAreas`, not from NFC.
