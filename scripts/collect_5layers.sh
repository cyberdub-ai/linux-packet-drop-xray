#!/usr/bin/env bash
# Read-only 5-layer Linux network packet drop snapshot collector (safe for production).
set -euo pipefail

IFACE="${1:-eth0}"
OUT="${2:-./xray_snapshot_$(date +%Y%m%d_%H%M%S)}"
BPF_SECS="${3:-10}"

mkdir -p "$OUT"
echo "[1/5] NIC & Ring Buffers (ethtool -S $IFACE)"
ethtool -S "$IFACE" > "$OUT/ethtool_s.txt" 2>/dev/null || true

echo "[2/5] SoftIRQ per-CPU backlog (/proc/net/softnet_stat)"
cp /proc/net/softnet_stat "$OUT/softnet_stat.txt"

echo "[3/5] Kernel qdisc stats (tc -s qdisc show dev $IFACE)"
tc -s qdisc show dev "$IFACE" > "$OUT/tc_qdisc.txt" 2>/dev/null || true

echo "[4/5] Live TCP sockets & SNMP counters (ss -tin + nstat -az)"
ss -tin > "$OUT/ss_tin.txt" 2>/dev/null || true
nstat -az > "$OUT/nstat.txt" 2>/dev/null || true

if command -v bpftrace >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
  echo "[5/5] eBPF kfree_skb trace (${BPF_SECS}s)"
  timeout "$BPF_SECS" bpftrace "$(dirname "$0")/../ebpf/kfree_skb_reasons.bt" > "$OUT/bpftrace_kfree_skb.txt" 2>/dev/null || true
else
  echo "[5/5] Skipping eBPF (requires root + bpftrace)"
fi

echo "Snapshot saved to: $OUT"
python3 -m packet_drop_xray analyze "$OUT" || true
