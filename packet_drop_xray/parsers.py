"""Pure-stdlib parsers for all 5 layers of Linux network packet drop telemetry."""

from __future__ import annotations

import re
from typing import Any


def parse_ethtool_stats(text: str) -> dict[str, int]:
    """Parse `ethtool -S <iface>` output into {counter_name: int_value}."""
    stats: dict[str, int] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("NIC statistics"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*:\s*(\d+)$", line)
        if m:
            stats[m.group(1)] = int(m.group(2))
    return stats


def parse_softnet_stat(text: str) -> list[dict[str, int]]:
    """Parse `/proc/net/softnet_stat` hex columns per CPU core.

    Columns (Linux kernel net/core/net-procfs.c):
      0: processed, 1: dropped, 2: time_squeeze, 9: received_rps, 10: flow_limit_count
    """
    cores: list[dict[str, int]] = []
    for cpu_idx, raw in enumerate(text.splitlines()):
        cols = raw.strip().split()
        if len(cols) < 3:
            continue
        try:
            vals = [int(c, 16) for c in cols]
        except ValueError:
            continue
        cores.append(
            {
                "cpu": cpu_idx,
                "processed": vals[0],
                "dropped": vals[1],
                "time_squeeze": vals[2],
                "received_rps": vals[9] if len(vals) > 9 else 0,
                "flow_limit_count": vals[10] if len(vals) > 10 else 0,
            }
        )
    return cores


def parse_tc_qdisc(text: str) -> list[dict[str, Any]]:
    """Parse `tc -s qdisc show` blocks into structured qdisc drop & overlimit metrics."""
    blocks: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m_hdr = re.match(r"^qdisc\s+(\S+)\s+\S+\s+dev\s+(\S+)", line)
        if m_hdr:
            cur = {
                "qdisc": m_hdr.group(1),
                "dev": m_hdr.group(2),
                "sent_bytes": 0,
                "sent_pkts": 0,
                "dropped": 0,
                "overlimits": 0,
                "requeues": 0,
            }
            blocks.append(cur)
            continue
        if cur is not None:
            m_sent = re.search(
                r"Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt\s+\(dropped\s+(\d+),\s+overlimits\s+(\d+)\s+requeues\s+(\d+)\)",
                line,
            )
            if m_sent:
                cur["sent_bytes"] = int(m_sent.group(1))
                cur["sent_pkts"] = int(m_sent.group(2))
                cur["dropped"] = int(m_sent.group(3))
                cur["overlimits"] = int(m_sent.group(4))
                cur["requeues"] = int(m_sent.group(5))
    return blocks


def parse_nstat(text: str) -> dict[str, int]:
    """Parse `nstat -az` SNMP/TcpExt kernel counters."""
    counters: dict[str, int] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            counters[parts[0]] = int(parts[1])
    return counters


def parse_ss_tin(text: str) -> dict[str, Any]:
    """Parse `ss -tin` socket lines for retransmits, lost packets, and high RTT."""
    sockets = 0
    total_retrans = 0
    total_lost = 0
    max_rtt_ms = 0.0
    hot_sockets: list[dict[str, Any]] = []
    last_header = ""

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("State"):
            continue
        if line.startswith(("ESTAB", "SYN-", "FIN-", "TIME-", "CLOSE-")):
            sockets += 1
            last_header = line
            continue
        m_ret = re.search(r"retrans:\d+/(\d+)", line)
        m_lost = re.search(r"lost:(\d+)", line)
        m_rtt = re.search(r"rtt:([0-9.]+)/([0-9.]+)", line)
        retrans = int(m_ret.group(1)) if m_ret else 0
        lost = int(m_lost.group(1)) if m_lost else 0
        rtt = float(m_rtt.group(1)) if m_rtt else 0.0
        total_retrans += retrans
        total_lost += lost
        max_rtt_ms = max(max_rtt_ms, rtt)
        if retrans > 0 or lost > 0 or rtt >= 100.0:
            hot_sockets.append(
                {
                    "socket": last_header[:90],
                    "retrans": retrans,
                    "lost": lost,
                    "rtt_ms": rtt,
                }
            )
    return {
        "sockets_scanned": sockets,
        "total_retrans": total_retrans,
        "total_lost": total_lost,
        "max_rtt_ms": round(max_rtt_ms, 2),
        "hot_sockets": hot_sockets,
    }


def parse_bpftrace_kfree_skb(text: str) -> list[dict[str, Any]]:
    """Parse bpftrace `@drops[reason, func]: count` map output."""
    entries: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^@drops\[([^,\]]+)(?:,\s*([^\]]+))?\]\s*:\s*(\d+)$", line)
        if m:
            entries.append(
                {
                    "reason": m.group(1).strip(),
                    "location": (m.group(2) or "unknown").strip(),
                    "count": int(m.group(3)),
                }
            )
    entries.sort(key=lambda e: e["count"], reverse=True)
    return entries
