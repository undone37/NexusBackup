# Scale-out — groundwork (Phase 8)

Status: design note (2026-10-10). Plan §1.2: multi-node clustering is a non-goal for the first releases; this
note records what is already node-independent, what is node-local today, and the intended path, so that new
code does not make scale-out harder.

## What already scales without changes
- **Chunk identity is content-addressed per tenant** (keyed BLAKE3). Any node can compute the ID of any chunk;
  deduplication needs no coordinator, only a shared answer to "does chunk X exist".
- **Sealed formats are location-independent**: chunks, indexes, manifests and packs are self-describing and bound
  to tenant + context via AAD, never to a node. Moving them between nodes needs no re-encryption.
- **Offsite and replication already work on the sealed formats** (`offsite::target`, `nexus-replica`): a node
  can rebuild its view from a remote copy (`rebuild_from_remote`, replica sync).
- **Connectors are separate processes** (`nexus-pve`, `nexus-agentctl`, `nexus-truenas`, `nexus-nas`, …) spawned
  with a generated config; they can run on any node that can reach the store and keyd.
- **Mark-and-sweep GC** needs no reference counts, so there are no cross-node counters to keep consistent.

## What is node-local today
| Component | Today | Scale-out direction |
|---|---|---|
| Chunk store | one directory tree per tenant on local XFS (`chunks/<prefix>/<id>`) | shard by chunk-ID prefix across nodes (consistent hashing over the 4-hex prefix); later erasure coding |
| Dedup lookup | file existence in the local store | per-shard lookup on the owning node (RPC), Bloom filters per shard |
| Snapshots (manifests + indexes) | local files | small; replicate to every node (or a metadata quorum of 3) |
| Catalog | SQLite (WAL) on one node | single active control-plane node with hot standby (catalog shipping), not a distributed DB, until proven necessary |
| Scheduler | one process | leader election (one active scheduler), jobs dispatched to worker nodes |
| keyd | one process per appliance, KEK in a file (TPM later) | per-node keyd with the KEK sealed to each node's TPM; tenant DEKs distributed wrapped (same mechanism as replication `export-for`) |
| GC | one pass over the local store | coordinated: mark on the metadata nodes, sweep per shard with the existing grace-period rule |
| Compliance clock | per store | per node + lock decisions made by the metadata quorum (max of clocks never shortens a lock) |

## Rules for new code (keep scale-out possible)
1. Address chunks only by ID through `Store` APIs; never assume a filesystem path outside `chunkstore`.
2. Keep connectors stateless apart from their generated config and the snapshot they read from the store.
3. New catalog tables must not hold data that only one node can produce (e.g. absolute local paths) without a node column.
4. Every long-running operation must be resumable from the catalog + store state (already true for backup commit order,
   offsite upload, replication sync).
5. No new process may require exclusive local access to the whole store except GC's sweep (which takes the chunk lock).

## Not done (by decision)
No sharding, no cluster membership, no RPC between nodes. The next step, when needed, is a two-node active/standby
control plane plus store sharding behind the existing `Store` API.
