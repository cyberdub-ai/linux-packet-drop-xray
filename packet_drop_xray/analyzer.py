"""5-layer Linux packet drop triage engine and remediation advisor."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .parsers import (
    parse_bpftrace_kfree_skb,
    parse_ethtool_stats,
    parse_nstat,
    parse_softnet_stat,
    parse_ss_tin,
    parse_tc_qdisc,
)

NIC_CRITICAL_KEYS = (
    "rx_missed_errors",
    "rx_no_buffer_count",
    "rx_crc_errors",
    "rx_over_errors",
    "rx_fifo_errors",
    "rx_dropped",
    "tx_dropped",
)

NSTAT_CRITICAL_KEYS = (
    "TcpExtListenOverflows",
    "TcpExtListenDrops",
    "TcpExtTCPRcvQDrop",
    "TcpExtTCPOFODrop",
    "IpExtInDiscards",
)


@dataclass(frozen=True)
class LayerFinding:
    layer: str
    severity: str  # "OK" | "WARN" | "CRITICAL"
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""


@dataclass
class XrayReport:
    target: str
    overall_severity: str
    critical_count: int
    warn_count: int
    ok_count: int
    findings: list[LayerFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "overall_severity": self.overall_severity,
            "critical_count": self.critical_count,
            "warn_count": self.warn_count,
            "ok_count": self.ok_count,
            "findings": [asdict(f) for f in self.findings],
        }


def analyze_snapshot_dir(snapshot_dir: str | Path) -> XrayReport:
    """Analyze a 5-layer Linux telemetry snapshot directory."""
    sdir = Path(snapshot_dir)
    findings: list[LayerFinding] = []

    # Layer 1: NIC & Ring Buffers (ethtool -S)
    eth_file = sdir / "ethtool_s.txt"
    if eth_file.exists():
        stats = parse_ethtool_stats(eth_file.read_text(encoding="utf-8", errors="replace"))
        hits = {k: v for k, v in stats.items() if v > 0 and any(ck in k.lower() for ck in NIC_CRITICAL_KEYS)}
        if hits:
            findings.append(
                LayerFinding(
                    layer="L1-NIC",
                    severity="CRITICAL",
                    summary=f"NIC ring-buffer or PHY drops detected ({len(hits)} non-zero error counter(s)).",
                    evidence=hits,
                    remediation="Inspect ring size with `ethtool -g <iface>` and raise RX/TX rings via `ethtool -G <iface> rx 4096 tx 4096`; verify SFP/cable if CRC errors grow.",
                )
            )
        else:
            findings.append(
                LayerFinding(
                    layer="L1-NIC",
                    severity="OK",
                    summary=f"Zero NIC ring/PHY error counters across {len(stats)} parsed metrics.",
                )
            )

    # Layer 2: SoftIRQ (/proc/net/softnet_stat)
    sn_file = sdir / "softnet_stat.txt"
    if sn_file.exists():
        cores = parse_softnet_stat(sn_file.read_text(encoding="utf-8", errors="replace"))
        tot_drop = sum(c["dropped"] for c in cores)
        tot_sqz = sum(c["time_squeeze"] for c in cores)
        hot_cpus = [c["cpu"] for c in cores if c["dropped"] > 0 or c["time_squeeze"] > 0]
        if tot_drop > 0:
            findings.append(
                LayerFinding(
                    layer="L2-SoftIRQ",
                    severity="CRITICAL",
                    summary=f"SoftIRQ backlog drops detected: dropped={tot_drop}, time_squeeze={tot_sqz} on CPUs {hot_cpus}.",
                    evidence={"dropped": tot_drop, "time_squeeze": tot_sqz, "hot_cpus": hot_cpus},
                    remediation="Increase `net.core.netdev_max_backlog=16384`, `net.core.netdev_budget=600`, `net.core.netdev_budget_usecs=8000`, and verify RSS/RPS IRQ affinity.",
                )
            )
        elif tot_sqz > 0:
            findings.append(
                LayerFinding(
                    layer="L2-SoftIRQ",
                    severity="WARN",
                    summary=f"SoftIRQ NAPI budget exhaustion (time_squeeze={tot_sqz}) on CPUs {hot_cpus}, zero drops so far.",
                    evidence={"dropped": 0, "time_squeeze": tot_sqz, "hot_cpus": hot_cpus},
                    remediation="Tune `net.core.netdev_budget=600` and spread NIC IRQ queues across CPU cores.",
                )
            )
        else:
            findings.append(
                LayerFinding(
                    layer="L2-SoftIRQ",
                    severity="OK",
                    summary=f"Clean SoftIRQ budget across {len(cores)} CPU core(s) (0 drops, 0 time_squeeze).",
                )
            )

    # Layer 3: Kernel Qdisc (tc -s qdisc)
    tc_file = sdir / "tc_qdisc.txt"
    if tc_file.exists():
        qdiscs = parse_tc_qdisc(tc_file.read_text(encoding="utf-8", errors="replace"))
        bad_q = [q for q in qdiscs if q["dropped"] > 0 or q["overlimits"] > 0]
        if bad_q:
            sev = "CRITICAL" if any(q["dropped"] > 0 for q in bad_q) else "WARN"
            findings.append(
                LayerFinding(
                    layer="L3-Qdisc",
                    severity=sev,
                    summary=f"Queue discipline congestion on {len(bad_q)} interface(s): "
                    + ", ".join(f"{q['dev']}({q['qdisc']} drop={q['dropped']} over={q['overlimits']})" for q in bad_q),
                    evidence={"qdiscs": bad_q},
                    remediation="Switch legacy `pfifo_fast` to `fq_codel` or `cake` (`tc qdisc replace dev <iface> root fq_codel`) and audit egress shaper burst limits.",
                )
            )
        else:
            findings.append(
                LayerFinding(
                    layer="L3-Qdisc",
                    severity="OK",
                    summary=f"Zero qdisc drops or overlimits across {len(qdiscs)} qdisc(s).",
                )
            )

    # Layer 4: Live TCP Sockets & Stack Counters (ss -tin + nstat -az)
    ss_file = sdir / "ss_tin.txt"
    nstat_file = sdir / "nstat.txt"
    if ss_file.exists() or nstat_file.exists():
        ss_res = parse_ss_tin(ss_file.read_text(encoding="utf-8", errors="replace")) if ss_file.exists() else {}
        nstat_res = parse_nstat(nstat_file.read_text(encoding="utf-8", errors="replace")) if nstat_file.exists() else {}
        bad_nstat = {k: nstat_res[k] for k in NSTAT_CRITICAL_KEYS if nstat_res.get(k, 0) > 0}
        retrans = ss_res.get("total_retrans", 0)
        lost = ss_res.get("total_lost", 0)
        if bad_nstat or lost > 0:
            findings.append(
                LayerFinding(
                    layer="L4-TCP",
                    severity="CRITICAL",
                    summary=f"TCP stack drops/overflows detected (nstat={bad_nstat}, socket_retrans={retrans}, lost={lost}).",
                    evidence={"nstat_critical": bad_nstat, "ss_summary": ss_res},
                    remediation="Raise `net.core.somaxconn=4096`, `net.ipv4.tcp_max_syn_backlog=4096`, enlarge `tcp_rmem`/`rmem_max`, and inspect slow application accept() loops.",
                )
            )
        elif retrans > 0:
            findings.append(
                LayerFinding(
                    layer="L4-TCP",
                    severity="WARN",
                    summary=f"Active TCP retransmissions observed (retrans={retrans}, max_rtt={ss_res.get('max_rtt_ms')}ms).",
                    evidence={"ss_summary": ss_res},
                    remediation="Run MTR/path-MTU check toward hot peers and verify upstream congestion.",
                )
            )
        else:
            findings.append(
                LayerFinding(
                    layer="L4-TCP",
                    severity="OK",
                    summary="Zero TCP listen overflows, rcvq drops, or active socket packet loss.",
                )
            )

    # Layer 5: eBPF Kernel Drop Reasons (bpftrace kfree_skb)
    bpf_file = sdir / "bpftrace_kfree_skb.txt"
    if bpf_file.exists():
        drops = parse_bpftrace_kfree_skb(bpf_file.read_text(encoding="utf-8", errors="replace"))
        # Ignore benign NOT_SPECIFIED / normal consumption if zero real drops
        real_drops = [d for d in drops if d["count"] > 0]
        if real_drops:
            top = real_drops[0]
            findings.append(
                LayerFinding(
                    layer="L5-eBPF",
                    severity="CRITICAL" if top["count"] >= 10 else "WARN",
                    summary=f"eBPF kfree_skb captured {sum(d['count'] for d in real_drops)} kernel drops; top reason={top['reason']} ({top['count']}x @ {top['location']}).",
                    evidence={"top_reasons": real_drops[:5]},
                    remediation="Correlate top `skb_drop_reason`: SOCKET_RCVBUFF -> raise rmem/app throughput; NETFILTER_DROP -> inspect `nft list ruleset`; NO_SOCKET -> verify port/listen backlog.",
                )
            )
        else:
            findings.append(
                LayerFinding(
                    layer="L5-eBPF",
                    severity="OK",
                    summary="Zero abnormal kfree_skb kernel drop reasons captured.",
                )
            )

    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    warn = sum(1 for f in findings if f.severity == "WARN")
    ok = sum(1 for f in findings if f.severity == "OK")
    overall = "CRITICAL" if crit > 0 else ("WARN" if warn > 0 else "OK")

    return XrayReport(
        target=str(sdir),
        overall_severity=overall,
        critical_count=crit,
        warn_count=warn,
        ok_count=ok,
        findings=findings,
    )
