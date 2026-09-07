# W2 — Evil-Twin Lab & Rogue-AP Detection `w2-evil-twin`

Defensive lab tooling for 802.11 evil-twin/rogue-AP detection and authorized lab setup.

## Overview

This project implements defensive analysis and authorized lab tooling for evil-twin/rogue-AP scenarios:
- **Beacon fingerprint detector**: Identifies cloned APs by IE blobs, beacon interval, channel, vendor OUI, and timing/sequence patterns
- **Clone detection**: Flags BSSIDs with identical fingerprints to known-legitimate APs
- **Timing analysis**: Detects non-standard beacon intervals and sequence anomalies
- **Config generator**: Produces hostapd/dnsmasq configuration templates for authorized lab reproduction
- **CSI integration point**: Documents channel state information as a physical-layer differentiator

## Features

- **IE-blob fingerprinting**: Clusters APs by Information Element content for clone detection
- **Multi-signal analysis**: Combines SSID, channel, beacon interval, OUI, capability bits, and IE data
- **Rogue vs legitimate classification**: Compares against a known-BSSID whitelist
- **Timing anomaly detection**: Flags non-standard beacon intervals and sequence-number irregularities
- **hostapd config generator**: Produces valid hostapd.conf for authorized lab setups
- **dnsmasq config generator**: Produces valid dnsmasq.conf for captive-portal lab networks
- **CSI fingerprint documentation**: Integration point for physical-layer AP differentiation
- **Offline demo**: Runs on 6 embedded sample beacon records

## Installation

```bash
# No external dependencies required for core functionality
# Optional: scapy for live packet capture (gracefully degraded if absent)
python3 firmware/evil_twin.py
```

## Usage

```bash
# Run the offline evil-twin simulation (prints exact frame bytes, NO radio emitted)
python3 firmware/evil_twin.py --i-understand-this-is-an-offline-lab-simulation-with-no-radio-emission \
    --simulate --lab-ssid lab-test-net --pcap-out reports/flow.pcap --json reports/w2.json

# Run the rogue-AP fingerprinter against the lab corpus
python3 firmware/evil_twin.py --detect

# Byte-exact unit tests
python3 -m unittest discover -s tests
```

A real-air refusal without the gate is enforced:
```bash
python3 firmware/evil_twin.py --simulate        # exit 2: safety flag required
python3 firmware/evil_twin.py --simulate --lab-ssid CorpNet   # exit 2: non-lab SSID refused
```

```python
from firmware.evil_twin import detect_rogue_aps, build_evil_twin_sequence
from firmware import frame_core as fc

# Build the full capture-flow frames as exact bytes (offscreen)
seq = build_evil_twin_sequence("lab-test-net")

# Detect clone APs from parsed beacon records
clones, fp_groups = detect_rogue_aps(beacon_list, known_bssids={"00:11:22:33:44:01"})
```

## Example Output

```
=================================================================
W2 — Evil-Twin Lab & Rogue-AP Detection
=================================================================

[+] Scanning embedded beacon records...
  aa:bb:cc:dd:ee:01  SSID=CorpNet-5G      ch= 36  interval=100ms  OUI=0050f2
  aa:bb:cc:dd:ee:02  SSID=CorpNet-5G      ch= 36  interval=100ms  OUI=0050f2
  ...

--- Beacon Fingerprinting ---
  Total BSSIDs scanned:     6
  Unique fingerprints:      2
  Clone detections:         6
  Rogue (non-legit) clones: 4
  Legitimate in group:      2

--- Clone Detection Report ---
  [ROGUE] aa:bb:cc:dd:ee:02  SSID=CorpNet-5G (clone of aa:bb:cc:dd:ee:01)
          Reason: Different BSSID with identical SSID+channel+beacon_interval+IE_blob+OUI+capability
  [LEGIT] aa:bb:cc:dd:ee:01  SSID=CorpNet-5G
          Reason: Known legitimate
  ...

--- Authorized Lab Config Templates ---
  [hostapd.conf] (3 lines shown)
    # hostapd configuration — LAB USE ONLY
    ...
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission before deploying any evil-twin or rogue-AP infrastructure
- Generating configurations for unauthorized access points is illegal
- This tool should ONLY be used in isolated lab environments you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized interception of network traffic and credential theft via rogue APs is a federal crime
- **Federal Communications Act (47 U.S.C. § 333)**: Operating unauthorized radio transmitters that interfere with licensed communications is prohibited
- **Wiretap Act (18 U.S.C. § 2511)**: Intercepting electronic communications without consent is illegal; capturing traffic via evil-twin APs may constitute wiretapping
- **State Laws**: Many states have additional computer crime and wiretapping statutes

### Acceptable Use
- Testing rogue-AP detection systems you own or operate
- Authorized penetration testing with written scope
- Academic research in isolated Faraday-cage lab environments
- Security education and training

### Prohibited Use
- Deploying evil-twin APs on networks you do not own without authorization
- Capturing user credentials or traffic via rogue APs
- Any activity that violates applicable laws or regulations
- Operating an intentional radiator outside FCC/regulatory limits

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## Live Lab Test Plan

This repo is a **pre-hardware simulation** tool. The evil-twin capture flow is built
offscreen as exact bytes and printed — **nothing is radiated** unless you add a hardware
backend plus an explicit gate.

Offline (this repo, no radio):
1. `python3 firmware/evil_twin.py --i-understand-this-is-an-offline-lab-simulation-with-no-radio-emission \
     --simulate --lab-ssid lab-test-net --json reports/w2.json` — build + print the beacon /
   probe / deauth-on-capture byte sequence (exit 0), inspect `reports/`.
2. Confirm the gate: `python3 firmware/evil_twin.py --simulate` **refuses** (exit 2) without the
   giant confirmation flag; a non-`lab-` SSID is also refused (exit 2).
3. `python3 -m unittest discover -s tests` — byte-exact unit tests pass (exit 0).

Authorized lab (only with hardware gate + written scope + shield + MAC/SSID allowlist):
4. On an air-gapped, shield-attenuated test bench on an authorized channel, transmit the exact
   bytes the simulation printed and confirm the lab monitor receives identical bytes.
5. Point lab detection (e.g., w2 rogue-AP detector / w7-wids-sensor) at the bench; confirm it
   flags the cloned-SSID rogue BSSID.
6. `green = permitted`: any real-air step requires prior written lab-owner authorization, the
   `--i-understand-...` + `--lab-ssid lab-*` allowlist, and a faraday/shielded enclosure.

## Metrics

- Frame types built byte-exact: beacon (cloned SSID), probe request, probe response,
  deauth-on-capture, auth (open)
- Capture flow: 7 deterministic phases, validated ordering on pcap fixture
- pcap (classic, linktype 105) write + read round-trip for offline fixtures
- Rogue-AP detection corpus: 5 lab beacons, clone detection by fingerprint
- Safety: `--i-understand-...` giant flag + `lab-*` SSID allowlist enforced before simulation

- Test suite: `python3 -m unittest discover -s tests`
- Reports: `reports/` (gitignored)

## License

MIT
