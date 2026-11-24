"""Unit and CLI tests for linux-packet-drop-xray (zero external dependencies)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from packet_drop_xray import (
    analyze_snapshot_dir,
    parse_bpftrace_kfree_skb,
    parse_ethtool_stats,
    parse_nstat,
    parse_softnet_stat,
    parse_ss_tin,
    parse_tc_qdisc,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
INCIDENT_DIR = REPO_ROOT / "examples" / "incident_snapshot"
HEALTHY_DIR = REPO_ROOT / "examples" / "healthy_snapshot"


class TestPacketDropXray(unittest.TestCase):
    def test_healthy_snapshot_is_all_ok(self) -> None:
        rep = analyze_snapshot_dir(HEALTHY_DIR)
        self.assertEqual(rep.overall_severity, "OK")
        self.assertEqual(rep.critical_count, 0)
        self.assertEqual(rep.warn_count, 0)
        self.assertEqual(rep.ok_count, 5)

    def test_incident_snapshot_flags_all_5_layers_critical(self) -> None:
        rep = analyze_snapshot_dir(INCIDENT_DIR)
        self.assertEqual(rep.overall_severity, "CRITICAL")
        self.assertEqual(rep.critical_count, 5)
        layers = {f.layer: f for f in rep.findings}
        self.assertEqual(layers["L1-NIC"].evidence["rx_missed_errors"], 412)
        self.assertEqual(layers["L2-SoftIRQ"].evidence["dropped"], 0x18)
        self.assertEqual(layers["L3-Qdisc"].evidence["qdiscs"][0]["dropped"], 184)
        self.assertEqual(layers["L4-TCP"].evidence["nstat_critical"]["TcpExtTCPRcvQDrop"], 64)
        self.assertEqual(layers["L5-eBPF"].evidence["top_reasons"][0]["reason"], "SKB_DROP_REASON_SOCKET_RCVBUFF")

    def test_parse_ethtool_stats(self) -> None:
        s = parse_ethtool_stats("NIC statistics:\n  rx_missed_errors: 12\n  rx_crc_errors: 3\n")
        self.assertEqual(s, {"rx_missed_errors": 12, "rx_crc_errors": 3})

    def test_parse_softnet_hex_decoding(self) -> None:
        cores = parse_softnet_stat("00000100 0000000a 00000010 0 0 0 0 0 0 00000002 00000001\n")
        self.assertEqual(len(cores), 1)
        self.assertEqual(cores[0]["processed"], 256)
        self.assertEqual(cores[0]["dropped"], 10)
        self.assertEqual(cores[0]["time_squeeze"], 16)
        self.assertEqual(cores[0]["received_rps"], 2)
        self.assertEqual(cores[0]["flow_limit_count"], 1)

    def test_softnet_time_squeeze_without_drops_is_warn(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "softnet_stat.txt").write_text("00010000 00000000 0000000f\n", encoding="utf-8")
            rep = analyze_snapshot_dir(p)
            self.assertEqual(rep.overall_severity, "WARN")
            self.assertEqual(rep.findings[0].layer, "L2-SoftIRQ")
            self.assertEqual(rep.findings[0].severity, "WARN")

    def test_parse_tc_qdisc_multiple_blocks(self) -> None:
        txt = (
            "qdisc fq_codel 0: dev eth0 root refcnt 2\n"
            " Sent 100 bytes 1 pkt (dropped 0, overlimits 5 requeues 0)\n"
            "qdisc htb 1: dev eth1 root refcnt 2\n"
            " Sent 200 bytes 2 pkt (dropped 7, overlimits 9 requeues 1)\n"
        )
        blocks = parse_tc_qdisc(txt)
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0]["overlimits"], 5)
        self.assertEqual(blocks[1]["dropped"], 7)

    def test_parse_ss_tin_and_nstat(self) -> None:
        ss = parse_ss_tin(
            "State Recv-Q Send-Q Local Peer\n"
            "ESTAB 0 100 10.0.0.1:443 10.0.0.2:12345\n"
            " cubic rtt:120.5/5.0 retrans:1/7 lost:2\n"
        )
        self.assertEqual(ss["sockets_scanned"], 1)
        self.assertEqual(ss["total_retrans"], 7)
        self.assertEqual(ss["total_lost"], 2)
        self.assertEqual(ss["max_rtt_ms"], 120.5)
        ns = parse_nstat("TcpExtListenOverflows 4 0.0\n")
        self.assertEqual(ns["TcpExtListenOverflows"], 4)

    def test_parse_bpftrace_sorts_descending(self) -> None:
        rows = parse_bpftrace_kfree_skb(
            "@drops[SKB_DROP_REASON_NO_SOCKET, udp_rcv]: 3\n"
            "@drops[SKB_DROP_REASON_NETFILTER_DROP, nf_hook_slow]: 42\n"
        )
        self.assertEqual(rows[0]["reason"], "SKB_DROP_REASON_NETFILTER_DROP")
        self.assertEqual(rows[0]["count"], 42)

    def test_cli_analyze_healthy_returns_zero(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "packet_drop_xray", "analyze", str(HEALTHY_DIR), "--json"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["overall_severity"], "OK")

    def test_cli_analyze_incident_returns_exit_code_2(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "packet_drop_xray", "analyze", str(INCIDENT_DIR), "--json"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 2, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["critical_count"], 5)


if __name__ == "__main__":
    unittest.main()
