# Security Policy

- All collectors (`scripts/collect_5layers.sh`, `packet_drop_xray collect`, `ebpf/kfree_skb_reasons.bt`) are strictly read-only and never modify NIC rings, sysctl parameters, qdiscs, or firewall rules automatically.
- All example IP addresses (`198.51.100.10`, `203.0.113.45`) follow RFC 5737 documentation space.
- Security reports: `alexey.zhuykov@gmail.com` (Subject: `[SECURITY] linux-packet-drop-xray`).
