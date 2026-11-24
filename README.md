# linux-packet-drop-xray

> **Zero-dependency 5-layer Linux network packet drop diagnostic toolkit (`ethtool -S`, `/proc/net/softnet_stat`, `tc -s qdisc`, `ss -tin` / `nstat`, and eBPF `kfree_skb`).**  
> Pinpoint *exactly* where Linux silently drops packets in under 5 minutes—with structured JSON triage, copy-paste sysctl/ethtool fixes, and a production-safe `bpftrace` probe.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](#)
[![Zero Dependencies](https://img.shields.io/badge/runtime%20deps-0%20(stdlib%20only)-brightgreen.svg)](#)
[![eBPF / bpftrace](https://img.shields.io/badge/eBPF-kfree__skb-0ea5e9.svg)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

![Linux Network Packet Drops & Bufferbloat Architecture](docs/architecture.png)

## Why This Exists

The hardest network incidents on Linux servers happen when **`ping` shows 0% loss** and CPU is 70% idle, yet microservices hit `context deadline exceeded`, VoIP calls stutter, or p99 latency spikes 10×.

`linux-packet-drop-xray` automates the **5-layer Linux packet-path triage** in one deterministic tool:

| Layer | Telemetry Source | What It Catches |
|---|---|---|
| **L1 — NIC & Ring Buffers** | `ethtool -S <iface>` | `rx_missed_errors`, `rx_no_buffer_count`, `rx_crc_errors`, `rx_dropped`, `tx_dropped` |
| **L2 — SoftIRQ Backlog** | `/proc/net/softnet_stat` | Hex-decoded per-CPU `dropped`, `time_squeeze` (NAPI budget exhaustion), RPS imbalances |
| **L3 — Kernel Qdisc** | `tc -s qdisc show` | `pfifo_fast` tail-drops, bufferbloat congestion, shaper `overlimits` & `requeues` |
| **L4 — TCP Stack & Sockets** | `ss -tin` + `nstat -az` | `TcpExtListenOverflows`, `TcpExtTCPRcvQDrop`, active socket `retrans` & `lost`, high RTT |
| **L5 — eBPF Drop Reasons** | `ebpf/kfree_skb_reasons.bt` | Exact Linux 5.17+ `enum skb_drop_reason` + kernel symbol (`SOCKET_RCVBUFF`, `NETFILTER_DROP`, `NO_SOCKET`) |

## Quickstart (30 seconds, zero `pip install` required)

```bash
git clone https://github.com/cyberdub-ai/linux-packet-drop-xray.git
cd linux-packet-drop-xray

# 1. Analyze the bundled realistic 5-layer incident snapshot
python -m packet_drop_xray analyze examples/incident_snapshot

# 2. Analyze the bundled healthy baseline snapshot
python -m packet_drop_xray analyze examples/healthy_snapshot

# 3. Run the full unit + CLI test suite (stdlib unittest, or pytest -v)
python -m unittest discover -s tests -v
```

## Run Live on a Linux Server (Strictly Read-Only)

```bash
# Collect all 5 layers (including optional 10s read-only eBPF kfree_skb trace if root + bpftrace)
sudo bash scripts/collect_5layers.sh eth0 ./incident_capture 10

# Or collect & analyze layers 1-4 directly via Python (no bash required)
python3 -m packet_drop_xray collect --iface eth0 --out ./snapshot --json
```

## Author

Built by **Alexey Zhuykov** — Telecom & AI Infrastructure Architect (19+ years in ISP operations, BGP/IPv6/Linux SRE, RIPE NCC Academy IPv6/BGP Security, Neo4j Certified Professional).  
Portfolio: [cyberdub.su](https://cyberdub.su) · Russian version: [README.ru.md](README.ru.md) · Companion repos: [frr-dual-isp-failover-lab](https://github.com/cyberdub-ai/frr-dual-isp-failover-lab) · [mcp-security-gateway](https://github.com/cyberdub-ai/mcp-security-gateway)
