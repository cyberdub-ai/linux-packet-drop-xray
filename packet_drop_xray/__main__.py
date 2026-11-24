"""CLI entrypoint for linux-packet-drop-xray."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from .analyzer import analyze_snapshot_dir


def _run_capture(cmd: list[str], out_file: Path) -> bool:
    if not shutil.which(cmd[0]):
        return False
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.stdout:
        out_file.write_text(proc.stdout, encoding="utf-8")
        return True
    return False


def collect_live(iface: str, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    _run_capture(["ethtool", "-S", iface], out_dir / "ethtool_s.txt")
    softnet = Path("/proc/net/softnet_stat")
    if softnet.exists():
        (out_dir / "softnet_stat.txt").write_text(softnet.read_text(encoding="utf-8"), encoding="utf-8")
    _run_capture(["tc", "-s", "qdisc", "show", "dev", iface], out_dir / "tc_qdisc.txt")
    _run_capture(["ss", "-tin"], out_dir / "ss_tin.txt")
    _run_capture(["nstat", "-az"], out_dir / "nstat.txt")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="packet_drop_xray",
        description="Zero-dependency 5-layer Linux packet drop analyzer (ethtool, softnet_stat, tc, ss/nstat, eBPF kfree_skb).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_an = sub.add_parser("analyze", help="Analyze a captured 5-layer telemetry directory")
    p_an.add_argument("snapshot_dir", help="Directory with ethtool_s.txt, softnet_stat.txt, tc_qdisc.txt, ss_tin.txt, nstat.txt, bpftrace_kfree_skb.txt")
    p_an.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    p_col = sub.add_parser("collect", help="Collect live read-only 4-layer Linux counters and analyze immediately")
    p_col.add_argument("--iface", required=True, help="Network interface (e.g. eth0, ens18)")
    p_col.add_argument("--out", default="./xray_snapshot", help="Output snapshot directory")
    p_col.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    args = parser.parse_args(argv)

    if args.cmd == "collect":
        out_dir = Path(args.out)
        collect_live(args.iface, out_dir)
        target = out_dir
    else:
        target = Path(args.snapshot_dir)

    report = analyze_snapshot_dir(target)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"=== Linux Packet Drop X-Ray: {report.target} ===")
        for f in report.findings:
            print(f"  [{f.severity:8s}] {f.layer:10s} | {f.summary}")
            if f.remediation:
                print(f"               FIX: {f.remediation}")
        print(
            f"OVERALL={report.overall_severity} (critical={report.critical_count}, "
            f"warn={report.warn_count}, ok={report.ok_count})"
        )
    return 0 if report.critical_count == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
