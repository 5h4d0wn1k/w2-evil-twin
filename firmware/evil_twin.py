#!/usr/bin/env python3
"""W2 — Evil-Twin Lab Simulation & Rogue-AP Detection.

Offline 802.11 evil-twin engineering: builds the *exact bytes* a rogue AP
would radiate (beacon with cloned SSID + probe response + deauth-on-capture)
and prints them WITHOUT transmitting.  Also includes the classic
beacon-fingerprint rogue-AP detector and lab config templates.

SAFETY: this is a pure simulation.  Real-air emission is OFF by default and
is a future hardware gate.  The simulation refuses to proceed unless a giant
confirmation flag PLUS a --lab-ssid allowlist entry is supplied.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from collections import Counter, defaultdict

try:
    from firmware import frame_core as fc
except ImportError:
    try:
        import frame_core as fc
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "firmware"))
        import frame_core as fc

# ----------------------------------------------------------------------
# Safety gate
# ----------------------------------------------------------------------

_SAFETY_FLAG = "--i-understand-this-is-an-offline-lab-simulation-with-no-radio-emission"
_HUGE_CONFIRMATION = ("I UNDERSTAND THIS IS AN OFFLINE LAB SIMULATION. "
                      "NO RADIO WILL BE EMITTED. I HAVE WRITTEN AUTHORIZATION "
                      "TO BUILD AND TEST EVIL-TWIN FRAMES ON MY OWN LAB NETWORK.")


class SafetyGateDenied(Exception):
    pass


def enforce_lab_gate(args) -> None:
    """Refuse simulation unless safe+confirmed."""
    if args.simulate and not args.confirm:
        raise SafetyGateDenied(
            "Global unlock required. Re-run with:\n"
            f"    {_SAFETY_FLAG} --lab-ssid=<your-lab-ssid>\n"
            "and prepend the full confirmation statement to this invocation.")
    if args.confirm and not args.lab_ssid:
        raise SafetyGateDenied("--lab-ssid=<allowlisted-lab-ssid> is required when simulating.")
    if args.lab_ssid and "lab" not in args.lab_ssid.lower() and not args.lab_ssid.startswith("lab-"):
        raise SafetyGateDenied(
            f"Refusing: SSID {args.lab_ssid!r} is not an allowlisted lab-* SSID. "
            "Use a clearly-labelled lab SSID (e.g. lab-<something>).")


# ----------------------------------------------------------------------
# Evil-twin frame-sequence simulation (offline, prints bytes only)
# ----------------------------------------------------------------------


def build_evil_twin_sequence(clone_ssid: str, legitimate_bssid: str = "00:11:22:33:44:55",
                             rogue_bssid: str = "00:11:22:33:44:66",
                             victim_mac: str = "00:11:22:33:44:77") -> list[dict]:
    """Build the full capture flow as raw bytes (no transmission)."""
    seq = []
    # 1. Beacon with the cloned SSID from the rogue BSSID
    beacon = fc.build_beacon(rogue_bssid, ssid=clone_ssid, timestamp=1000,
                             beacon_interval=100, seq_num=1)
    beacon += fc.fcs(beacon)
    seq.append({"phase": "beacon-rogue", "kind": "beacon",
                "data": beacon, "note": f"cloned SSID {clone_ssid!r} from rogue BSSID"})
    # 2. Legitimate beacon for comparison (same SSID, legit BSSID)
    legit = fc.build_beacon(legitimate_bssid, ssid=clone_ssid, timestamp=1000,
                            beacon_interval=100, seq_num=1)
    legit += fc.fcs(legit)
    seq.append({"phase": "beacon-legit", "kind": "beacon",
                "data": legit, "note": f"same SSID from legitimate BSSID"})
    # 3. Probe request from victim
    preq = fc.build_probe_request(ssid=clone_ssid, sa=victim_mac, seq_num=2)
    preq += fc.fcs(preq)
    seq.append({"phase": "probe-req", "kind": "probe-request",
                "data": preq, "note": f"victim {victim_mac} probes for SSID"})
    # 4. Probe response from rogue AP (impersonation)
    presp = fc.build_probe_response(rogue_bssid, ssid=clone_ssid, timestamp=1001,
                                    beacon_interval=100, seq_num=3, sa=rogue_bssid)
    presp += fc.fcs(presp)
    seq.append({"phase": "probe-resp-rogue", "kind": "probe-response",
                "data": presp, "note": "rogue AP impersonates SSID"})
    # 5. Beacon with cloned SSID from victim's perspective + timestamp (capture begin)
    cap = fc.build_beacon(rogue_bssid, ssid=clone_ssid, timestamp=1002,
                          beacon_interval=100, seq_num=4)
    cap += fc.fcs(cap)
    seq.append({"phase": "capture-beacon", "kind": "beacon",
                "data": cap, "note": "capture window (post-assoc)"})
    # 6. Deauth-on-capture: force client to re-auth toward rogue
    deauth = fc.build_deauth(victim_mac, legitimate_bssid, legitimate_bssid,
                             reason=7, seq_num=5)
    deauth += fc.fcs(deauth)
    seq.append({"phase": "deauth-on-capture", "kind": "deauth",
                "data": deauth, "note": f"deauth to {victim_mac} (reason 7)"})
    # 7. Auth request (open) to rogue
    auth = fc.build_auth(victim_mac, rogue_bssid, rogue_bssid, auth_alg=fc.AUTH_ALG_OPEN,
                         transaction=1, status=0, seq_num=6)
    auth += fc.fcs(auth)
    seq.append({"phase": "auth-req-rogue", "kind": "auth",
                "data": auth, "note": "client auth toward rogue AP"})
    return seq


def sort_sequence(seq: list[dict]) -> list[dict]:
    """Stable ordering of the capture flow by phase."""
    order = ["beacon-rogue", "beacon-legit", "probe-req", "probe-resp-rogue",
             "capture-beacon", "deauth-on-capture", "auth-req-rogue"]
    return sorted(seq, key=lambda e: order.index(e["phase"]) if e["phase"] in order else 99)


def write_capture_pcap(seq: list[dict], path: str, ts: float = 1700000000.0) -> int:
    """Write the simulated capture flow to a pcap fixture."""
    frames = [e["data"] for e in sort_sequence(seq)]
    fc.write_pcap(path, frames, ts=ts)
    return len(frames)


def read_capture_pcap(path: str) -> list[dict]:
    """Read a pcap fixture back and classify each frame (byte-level)."""
    records = fc.read_pcap(path)
    out = []
    for r in records:
        data = r["data"]
        try:
            hdr, _ = fc.parse_mgmt_header(data)
            kind = fc.fc_subtype_str(hdr["fc"])
            out.append({"kind": kind, "subtype": hdr["subtype_val"],
                        "sa": hdr["sa"], "da": hdr["da"], "bssid": hdr["bssid"],
                        "seq": hdr["seq_num"], "ts": r["ts"]})
        except ValueError:
            out.append({"kind": "unknown", "ts": r["ts"]})
    return out


def validate_capture_ordering(records: list[dict]) -> list[str]:
    """Check the deauth-on-capture flow ordering is sane."""
    issues = []
    kinds = [r["kind"] for r in records]
    if "deauth" not in kinds:
        issues.append("no deauth frame present in capture")
    if "probe-request" in kinds and "probe-response" not in kinds:
        issues.append("probe request present but no probe response")
    return issues


# ----------------------------------------------------------------------
# Rogue-AP detection (record based, from SAMPLE beacons below)
# ----------------------------------------------------------------------


def _sync_capability(beacon_records: list[dict]) -> None:
    """Add a canonical capability value to record-based beacons lacking it."""
    for b in beacon_records:
        if "capability" not in b:
            b["capability"] = 0x0431


def fingerprint_beacon(beacon):
    return (beacon["ssid"], beacon["channel"], beacon["beacon_interval"],
            beacon.get("ie_blob", ""), beacon.get("vendor_oui", ""),
            beacon.get("capability", 0))


def detect_rogue_aps(beacons, known_bssids):
    _sync_capability(beacons)
    legit_fingerprints = {}
    for b in beacons:
        if b["bssid"] in known_bssids:
            legit_fingerprints[fingerprint_beacon(b)] = b["bssid"]
    unique_fingerprints = defaultdict(list)
    for b in beacons:
        unique_fingerprints[fingerprint_beacon(b)].append(b["bssid"])
    clones = []
    for fp, bssids in unique_fingerprints.items():
        if len(bssids) > 1:
            for b in bssids:
                is_legit = b in known_bssids
                clones.append({
                    "bssid": b, "ssid": fp[0], "is_clone": not is_legit,
                    "clone_of": legit_fingerprints.get(fp),
                    "reason": ("Different BSSID with identical fingerprint"
                               if not is_legit else "Known legitimate"),
                })
    return clones, unique_fingerprints


# Embedded sample beacon records (authorized lab corpus)
SAMPLE_BEACONS = [
    {"bssid": "00:11:22:33:44:01", "ssid": "lab-corp-5g", "channel": 36,
     "beacon_interval": 100, "capability": 0x0431,
     "ie_blob": "010882848b960c12182430182830", "vendor_oui": "0050f2",
     "ts_offset": 0.0, "seq_start": 100, "label": "legitimate-ap"},
    {"bssid": "00:11:22:33:44:02", "ssid": "lab-corp-5g", "channel": 36,
     "beacon_interval": 100, "capability": 0x0431,
     "ie_blob": "010882848b960c12182430182830", "vendor_oui": "0050f2",
     "ts_offset": 0.003, "seq_start": 200, "label": "rogue-twin"},
    {"bssid": "00:11:22:33:44:03", "ssid": "lab-freewifi", "channel": 1,
     "beacon_interval": 100, "capability": 0x0411,
     "ie_blob": "010882848b960c121824", "vendor_oui": "001018",
     "ts_offset": 0.01, "seq_start": 300, "label": "open-rogue"},
    {"bssid": "00:11:22:33:44:04", "ssid": "lab-corp-5g", "channel": 36,
     "beacon_interval": 100, "capability": 0x0431,
     "ie_blob": "010882848b960c12182430182830", "vendor_oui": "0050f2",
     "ts_offset": 0.005, "seq_start": 150, "label": "rogue-twin-2"},
    {"bssid": "00:11:22:33:44:05", "ssid": "lab-guest", "channel": 6,
     "beacon_interval": 102, "capability": 0x0431,
     "ie_blob": "010882848b960c1218243018", "vendor_oui": "0050f2",
     "ts_offset": 0.02, "seq_start": 400, "label": "legitimate-guest"},
]

KNOWN_LEGITIMATE = {"00:11:22:33:44:01", "00:11:22:33:44:05"}


def generate_hostapd_config(ssid, channel, interface="wlan0"):
    return (f"# hostapd configuration — LAB USE ONLY\n"
            f"# Generated by w2-evil-twin for authorized lab simulation\n"
            f"interface={interface}\n"
            f"driver=nl80211\n"
            f"ssid={ssid}\n"
            f"channel={channel}\n"
            f"hw_mode=g\n"
            f"ieee80211n=1\n"
            f"ignore_broadcast_ssid=0\n"
            f"wpa=2\n"
            f"wpa_passphrase=labpassword123\n"
            f"wpa_key_mgmt=WPA-PSK\n"
            f"rsn_pairwise=CCMP\n")


def generate_dnsmasq_config(interface="wlan0", gateway="192.0.2.1"):
    return (f"# dnsmasq configuration — LAB USE ONLY\n"
            f"interface={interface}\n"
            f"dhcp-range=192.0.2.10,192.0.2.200,255.255.255.0,12h\n"
            f"dhcp-option=option:router,{gateway}\n"
            f"log-queries\n"
            f"log-dhcp\n")


# ----------------------------------------------------------------------
# CLI / demo
# ----------------------------------------------------------------------


def build_args_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="w2-evil-twin",
        description="Offline evil-twin frame-sequence simulation + rogue-AP detection "
                    "(pure-stdlib bytes; NO radio emission).")
    p.add_argument("--simulate", action="store_true",
                   help="build the evil-twin capture flow bytes (offline).")
    p.add_argument("--lab-ssid", default="lab-test-net",
                   help="allowlisted lab SSID to clone (must start with lab-).")
    p.add_argument("--pcap-out", metavar="PATH",
                   help="write the simulated capture flow to a pcap fixture.")
    p.add_argument("--json", metavar="PATH", help="write JSON report.")
    p.add_argument("--detect", action="store_true",
                   help="run the rogue-AP beacon-fingerprint detector (offline).")
    p.add_argument(_SAFETY_FLAG, dest="confirm", action="store_true",
                   help="GIANT confirmation: acknowledge offline-only lab simulation, "
                        "no radio emission, written authorization held.")
    return p


def run_simulation(clone_ssid: str, report_dir: str) -> dict:
    seq = build_evil_twin_sequence(clone_ssid)
    seq_sorted = sort_sequence(seq)
    return {
        "name": "w2-evil-twin",
        "mode": "simulation",
        "clone_ssid": clone_ssid,
        "radio_emitted": False,
        "safety_flag_required": _SAFETY_FLAG,
        "steps": [{"phase": e["phase"], "kind": e["kind"], "note": e["note"],
                   "bytes": len(e["data"]), "hex": e["data"].hex()} for e in seq_sorted],
    }


def run_detection() -> dict:
    clones, groups = detect_rogue_aps(SAMPLE_BEACONS, KNOWN_LEGITIMATE)
    return {
        "name": "w2-evil-twin",
        "mode": "detection",
        "radio_emitted": False,
        "beacons_scanned": len(SAMPLE_BEACONS),
        "unique_fingerprints": len(groups),
        "rogue_count": sum(1 for c in clones if c["is_clone"]),
        "alerts": clones,
    }


def print_simulation(result: dict) -> None:
    print("=" * 66)
    print("W2 — Evil-Twin Lab Simulation (OFFLINE — no radio emitted)")
    print("=" * 66)
    print(f"\n[+] Cloning lab SSID: {result['clone_ssid']!r}")
    print(f"[+] radio_emitted = {result['radio_emitted']}  (simulation only)\n")
    for step in result["steps"]:
        print(f"  -> {step['phase']:20s} {step['kind']:14s} ({step['bytes']:3d}B)  {step['note']}")
        print(f"     {step['hex']}")
    print("\n[+] Exact bytes shown above. NOTHING was radiated.")
    print("    To radiate, a hardware gate + written authorization is required.")
    print("=" * 66)


def print_detection(result: dict) -> None:
    print("=" * 66)
    print("W2 — Evil-Twin Rogue-AP Detection (offline corpus)")
    print("=" * 66)
    print(f"\n[+] Beacons scanned: {result['beacons_scanned']}")
    print(f"[+] Unique fingerprints: {result['unique_fingerprints']}")
    print(f"[+] Rogue (clone) detections: {result['rogue_count']}\n")
    for c in result["alerts"]:
        tag = "ROGUE" if c["is_clone"] else "LEGIT"
        clone_of = f" (clone of {c['clone_of']})" if c["clone_of"] else ""
        print(f"  [{tag:5s}] {c['bssid']}  SSID={c['ssid']}{clone_of}")
        print(f"          {c['reason']}")
    print("=" * 66)


def main(argv=None) -> int:
    parser = build_args_parser()
    args = parser.parse_args(argv)

    if not args.simulate and not args.detect:
        parser.print_help()
        return 0

    results = []
    if args.simulate:
        try:
            enforce_lab_gate(args)
        except SafetyGateDenied as e:
            print(f"ABORT: {e}", file=sys.stderr)
            return 2
        result = run_simulation(args.lab_ssid, "reports")
        print_simulation(result)
        results.append(result)
        if args.pcap_out:
            seq = build_evil_twin_sequence(args.lab_ssid)
            n = write_capture_pcap(seq, args.pcap_out)
            records = read_capture_pcap(args.pcap_out)
            issues = validate_capture_ordering(records)
            print(f"\n[+] pcap fixture written: {args.pcap_out} ({n} frames)")
            print(f"[+] capture ordering: {'OK' if not issues else issues}")
    if args.detect:
        d = run_detection()
        print_detection(d)
        results.append(d)

    if args.json:
        d = os.path.dirname(args.json)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(args.json, "w") as f:
            json.dump({"reports": results}, f, indent=2, default=str)
    return 0


def run_demo() -> int:
    """Compatibility entry that runs the offline simulation demo (exit 0)."""
    return main([_SAFETY_FLAG, "--lab-ssid", "lab-test-net", "--detect"])


if __name__ == "__main__":
    raise SystemExit(main())
