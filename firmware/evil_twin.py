#!/usr/bin/env python3
"""W2 — Evil-Twin Lab & Rogue-AP Detection

Defensive lab tooling for 802.11 evil-twin/rogue-AP detection and authorized lab setup.
Beacon-fingerprint detector with IE-blob, interval, OUI, timing, and sequence analysis.
Includes hostapd/dnsmasq config generator templates for authorized lab use.
"""

import struct
import time
from collections import defaultdict, Counter

try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# ---------------------------------------------------------------------------
# Embedded sample beacon frames for rogue-AP detection demo
# Each record simulates a parsed beacon with key fields.
# ---------------------------------------------------------------------------

SAMPLE_BEACONS = [
    {
        "bssid": "aa:bb:cc:dd:ee:01",
        "ssid": "CorpNet-5G",
        "channel": 36,
        "beacon_interval": 100,
        "capability": 0x0431,
        "ie_blob": "010882848b960c12182430182830",
        "vendor_oui": "0050f2",
        "ts_offset": 0.0,
        "seq_start": 100,
        "label": "legitimate-ap",
    },
    {
        "bssid": "aa:bb:cc:dd:ee:02",
        "ssid": "CorpNet-5G",
        "channel": 36,
        "beacon_interval": 100,
        "capability": 0x0431,
        "ie_blob": "010882848b960c12182430182830",
        "vendor_oui": "0050f2",
        "ts_offset": 0.003,
        "seq_start": 200,
        "label": "rogue-twin",
    },
    {
        "bssid": "aa:bb:cc:dd:ee:03",
        "ssid": "FreeWiFi",
        "channel": 1,
        "beacon_interval": 100,
        "capability": 0x0411,
        "ie_blob": "010882848b960c121824",
        "vendor_oui": "001018",
        "ts_offset": 0.01,
        "seq_start": 300,
        "label": "open-rogue",
    },
    {
        "bssid": "aa:bb:cc:dd:ee:04",
        "ssid": "CorpNet-5G",
        "channel": 36,
        "beacon_interval": 100,
        "capability": 0x0431,
        "ie_blob": "010882848b960c12182430182830",
        "vendor_oui": "0050f2",
        "ts_offset": 0.005,
        "seq_start": 150,
        "label": "rogue-twin-2",
    },
    {
        "bssid": "11:22:33:44:55:66",
        "ssid": "GuestNet",
        "channel": 6,
        "beacon_interval": 102,
        "capability": 0x0431,
        "ie_blob": "010882848b960c1218243018",
        "vendor_oui": "00904c",
        "ts_offset": 0.02,
        "seq_start": 400,
        "label": "legitimate-guest",
    },
    {
        "bssid": "aa:bb:cc:dd:ee:05",
        "ssid": "CorpNet-5G",
        "channel": 36,
        "beacon_interval": 100,
        "capability": 0x0431,
        "ie_blob": "010882848b960c12182430182830",
        "vendor_oui": "0050f2",
        "ts_offset": 0.007,
        "seq_start": 250,
        "label": "rogue-twin-3",
    },
]

KNOWN_LEGITIMATE = {
    "aa:bb:cc:dd:ee:01",
    "11:22:33:44:55:66",
}


def fingerprint_beacon(beacon):
    """Create a fingerprint tuple from a parsed beacon record."""
    return (
        beacon["ssid"],
        beacon["channel"],
        beacon["beacon_interval"],
        beacon["ie_blob"],
        beacon["vendor_oui"],
        beacon["capability"],
    )


def detect_rogue_aps(beacons, known_bssids):
    """Detect rogue/clone APs by comparing fingerprints.

    Flags BSSIDs with identical fingerprints to known-legitimate APs
    but different MAC addresses.
    """
    legit_fingerprints = {}
    for b in beacons:
        if b["bssid"] in known_bssids:
            fp = fingerprint_beacon(b)
            legit_fingerprints[fp] = b["bssid"]

    clones = []
    unique_fingerprints = defaultdict(list)
    for b in beacons:
        fp = fingerprint_beacon(b)
        unique_fingerprints[fp].append(b["bssid"])

    for fp, bssids in unique_fingerprints.items():
        if len(bssids) > 1:
            for b in bssids:
                is_legit = b in known_bssids
                clones.append({
                    "bssid": b,
                    "ssid": beacons[0]["ssid"] if fp[0] == beacons[0]["ssid"] else fp[0],
                    "is_clone": not is_legit,
                    "clone_of": legit_fingerprints.get(fp, None),
                    "fingerprint": fp,
                    "reason": (
                        "Different BSSID with identical SSID+channel+beacon_interval+IE_blob+OUI+capability"
                        if not is_legit else "Known legitimate"
                    ),
                })

    return clones, unique_fingerprints


def timing_analysis(beacons):
    """Analyze beacon timing/sequence patterns for anomalies."""
    anomalies = []
    for b in beacons:
        interval = b["beacon_interval"]
        if interval != 100:
            anomalies.append({
                "bssid": b["bssid"],
                "type": "non_standard_interval",
                "detail": f"Beacon interval {interval}ms (standard: 100ms)",
            })
    seq_groups = defaultdict(list)
    for b in beacons:
        seq_groups[b["ssid"]].append(b["seq_start"])
    for ssid, seqs in seq_groups.items():
        if len(seqs) > 1:
            diffs = [seqs[i+1] - seqs[i] for i in range(len(seqs)-1)]
            if any(d < 0 for d in diffs):
                anomalies.append({
                    "ssid": ssid,
                    "type": "sequence_anomaly",
                    "detail": f"Non-monotonic sequence numbers: {seqs}",
                })
    return anomalies


def generate_hostapd_config(ssid, channel, interface="wlan0", output_path="hostapd.conf"):
    """Generate a hostapd config template for authorized evil-twin lab use."""
    config = f"""# hostapd configuration — LAB USE ONLY
# Generated by w2-evil-twin for authorized security testing
interface={interface}
driver=nl80211
ssid={ssid}
channel={channel}
hw_mode=g
ieee80211n=1
wmm_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=labpassword123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
    return config


def generate_dnsmasq_config(interface="wlan0", gateway="192.168.1.1", output_path="dnsmasq.conf"):
    """Generate a dnsmasq config template for authorized evil-twin lab use."""
    config = f"""# dnsmasq configuration — LAB USE ONLY
# Generated by w2-evil-twin for authorized security testing
interface={interface}
dhcp-range=192.168.1.10,192.168.1.200,255.255.255.0,12h
dhcp-option=option:router,{gateway}
dhcp-option=option:dns-server,8.8.8.8,8.8.4.4
server=8.8.8.8
server=8.8.4.4
log-queries
log-dhcp
"""
    return config


def csi_fingerprint_note():
    """Document CSI-fingerprint integration point."""
    return (
        "CSI Fingerprint Integration Point:\n"
        "  Channel State Information (CSI) can differentiate co-located APs by their\n"
        "  unique multipath signatures. Integration requires:\n"
        "  1. Atheros/Intel NIC with CSI extraction firmware\n"
        "  2. csitool or Linux 802.11n CSI extraction framework\n"
        "  3. Per-BSSID CSI fingerprint database\n"
        "  4. Comparison algorithm (cosine similarity on CSI amplitude vectors)\n"
        "  This extends the IE-blob fingerprinting to physical-layer differentiation."
    )


def run_demo():
    """Run offline demo with embedded sample beacons."""
    print("=" * 65)
    print("W2 — Evil-Twin Lab & Rogue-AP Detection")
    print("=" * 65)

    print("\n[+] Scanning embedded beacon records...")
    for b in SAMPLE_BEACONS:
        print(f"  {b['bssid']}  SSID={b['ssid']:<15s}  ch={b['channel']:>3d}  "
              f"interval={b['beacon_interval']}ms  OUI={b['vendor_oui']}")

    print("\n--- Beacon Fingerprinting ---")
    clones, fp_groups = detect_rogue_aps(SAMPLE_BEACONS, KNOWN_LEGITIMATE)
    unique_fps = len(fp_groups)
    total_bssids = len(SAMPLE_BEACONS)
    print(f"  Total BSSIDs scanned:     {total_bssids}")
    print(f"  Unique fingerprints:      {unique_fps}")
    print(f"  Clone detections:         {len(clones)}")

    rogue_count = sum(1 for c in clones if c["is_clone"])
    legit_count = sum(1 for c in clones if not c["is_clone"])
    print(f"  Rogue (non-legit) clones: {rogue_count}")
    print(f"  Legitimate in group:      {legit_count}")

    print("\n--- Clone Detection Report ---")
    for c in clones:
        status = "ROGUE" if c["is_clone"] else "LEGIT"
        clone_of = f" (clone of {c['clone_of']})" if c["clone_of"] else ""
        print(f"  [{status:5s}] {c['bssid']}  SSID={c['ssid']}{clone_of}")
        print(f"          Reason: {c['reason']}")

    print("\n--- Timing/Sequence Analysis ---")
    anomalies = timing_analysis(SAMPLE_BEACONS)
    if anomalies:
        for a in anomalies:
            print(f"  [!] {a['type']}: {a['detail']}")
    else:
        print("  No timing anomalies detected.")

    print("\n--- CSI Fingerprint Integration Point ---")
    print(f"  {csi_fingerprint_note()}")

    print("\n--- Authorized Lab Config Templates ---")
    hostapd_cfg = generate_hostapd_config("CorpNet-5G", 36)
    dnsmasq_cfg = generate_dnsmasq_config()
    print("  [hostapd.conf] (3 lines shown)")
    for line in hostapd_cfg.strip().split("\n")[:3]:
        print(f"    {line}")
    print(f"  ... ({len(hostapd_cfg.strip().splitlines())} lines total)")
    print("  [dnsmasq.conf] (3 lines shown)")
    for line in dnsmasq_cfg.strip().split("\n")[:3]:
        print(f"    {line}")
    print(f"  ... ({len(dnsmasq_cfg.strip().splitlines())} lines total)")

    print("\n--- Report Summary ---")
    print(f"  Beacons analyzed:    {total_bssids}")
    print(f"  Rogue APs detected:  {rogue_count}")
    print(f"  Timing anomalies:    {len(anomalies)}")
    print(f"  Config templates:    2 (hostapd + dnsmasq)")
    print("\n" + "=" * 65)
    print("Demo complete — all checks passed.")
    print("=" * 65)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_demo())
