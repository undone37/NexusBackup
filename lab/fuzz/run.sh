#!/usr/bin/env bash
# Runs the cargo-fuzz targets (docs/security-review.md, "Fuzzing").
#
#   lab/fuzz/run.sh [SECONDS] [PARALLEL] [crate:target ...]
#
# Defaults: 600 s per target, 4 targets at a time, all targets. Needs a nightly
# toolchain and cargo-fuzz (`rustup toolchain install nightly`,
# `cargo install cargo-fuzz`). Corpora grow in crates/<crate>/fuzz/corpus/<target>
# (git-ignored), seeded from crates/<crate>/fuzz/seeds/<target>; crashes land in
# crates/<crate>/fuzz/artifacts/<target>. SANITIZER=address enables ASan
# (slower, ~3x memory). TIMEOUT=<s> per input (default 60; slow units on a
# loaded machine are not bugs). Logs: target/fuzz-logs/<target>.log.
set -euo pipefail
cd "$(dirname "$0")/../.."
secs=${1:-600}
par=${2:-4}
shift $(($# < 2 ? $# : 2))
all=(nbd:nbd_client nbd:nbd_server chunkstore:sealed_open chunkstore:meta_decode
     offsite:pack_parse offsite:hostile_box offsite:s3_xml pve:ct_records pve:tar_files pve:agent_frames
     pve:agent_request keyd:keyd_request keyd:hybrid_open web-api:validators web-api:api_router truenas:hostile_stream
     nas:helper_request replication:hostile_primary plugin-host:hostile_plugin
     fsindex:part_table fsindex:lvm_meta fsindex:ext4_walk fsindex:ntfs_walk fsindex:fat_walk
     fsindex:exfat_walk fsindex:helper_frames fsindex:disk_walk)
if [ $# -gt 0 ]; then targets=("$@"); else targets=("${all[@]}"); fi
san=${SANITIZER:-none}
logs=target/fuzz-logs
mkdir -p "$logs"

python3 lab/fuzz/mkseeds.py . >/dev/null
for c in $(printf '%s\n' "${targets[@]}" | cut -d: -f1 | sort -u); do
  (cd "crates/$c/fuzz/.." && cargo +nightly fuzz build -s "$san" --target-dir ../../target/fuzz >/dev/null)
done
if printf '%s\n' "${targets[@]}" | grep -q '^offsite:' && [ ! -e crates/offsite/fuzz/seeds/hostile_box/upload3 ]; then
  (cd crates/offsite/fuzz && cargo +nightly run -q --example mkseed --target-dir ../../../target/fuzz-seed -- seeds)
fi

run() {
  local c=${1%%:*} t=${1##*:} rc=0
  mkdir -p "crates/$c/fuzz/corpus/$t" "crates/$c/fuzz/seeds/$t"
  (cd "crates/$c" && cargo +nightly fuzz run -s "$san" --target-dir ../../target/fuzz "$t" \
     "fuzz/corpus/$t" "fuzz/seeds/$t" -- -max_total_time="$secs" -rss_limit_mb=1024 \
     -max_len=65536 -timeout="${TIMEOUT:-60}" -print_final_stats=1) >"$logs/$t.log" 2>&1 || rc=$?
  printf '%-14s %-6s %s\n' "$t" "$([ $rc = 0 ] && echo ok || echo CRASH)" \
    "$(grep -E '^stat::number_of_executed_units' "$logs/$t.log" | awk '{print $2 " execs"}')"
}

running=0
for x in "${targets[@]}"; do
  run "$x" &
  running=$((running + 1))
  if [ "$running" -ge "$par" ]; then wait -n || true; running=$((running - 1)); fi
done
wait
