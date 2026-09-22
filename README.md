> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# W2 — Evil-Twin Lab & Rogue-AP Detection Toolkit

[![License](https://img.shields.io/github/license/5h4d0wn1k/w2-evil-twin)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/w2-evil-twin)](https://github.com/5h4d0wn1k/w2-evil-twin/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/5h4d0wn1k/w2-evil-twin)](https://github.com/5h4d0wn1k/w2-evil-twin/commits/master)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/w2-evil-twin)](https://github.com/5h4d0wn1k/w2-evil-twin/issues)

**W2** is a lab-oriented toolkit for 802.11 evil-twin and rogue-AP detection:
it fingerprints beacon frames to identify cloned access points, classifies rogue
vs legitimate BSSIDs, generates hostapd/dnsmasq lab configs, and simulates the
full evil-twin frame exchange — all offscreen, without emitting radio.

## Why W2?

Evil-twin attacks remain one of the most effective Wi-Fi security threats, and
defending against them requires understanding how clones are shaped at the
frame level. W2 teaches that in a safe, deterministic sandbox: it clusters APs
by Information-Element content and capabilities, compares beacons against a
known-BSSID whitelist, flags timing and sequence anomalies, and reproduces
byte-exact evil-twin captures to a pcap via `frame_core.py`. A strict lab gate
refuses real-air simulation unless the full safety flag is supplied — keeping
the whole exercise firmly educational and authorized.

## Features

- **IE-blob beacon fingerprinting** — clusters APs by Information Element
  content, capability bits, OUI, channel, and beacon interval
  (`firmware/evil_twin.py`).
- **Rogue vs legitimate classification** — compares captured BSSIDs against a
  known whitelist (`detect_rogue_aps`).
- **Offline evil-twin simulation** — builds the full clone-AP frame sequence as
  exact bytes and writes it to a pcap (`build_evil_twin_sequence`,
  `write_capture_pcap`); no radio transmitted.
- **Safety-gated execution** — simulation is refused without the explicit
  offline-lab flag and non-lab SSIDs are blocked (`enforce_lab_gate`).
- **hostapd & dnsmasq config generators** — template generators for authorized
  lab access-point and captive-portal networks.
- **CSI documentation point** — channel-state-information integration notes for
  physical-layer differentiation.
- **Byte-exact unit tests** — `python3 -m unittest discover -s tests`.

## Quickstart

### Requirements

- Python 3.8+ (stdlib only; scapy optional for live capture)

### Run the offline simulation (requires the safety gate)

```bash
python3 firmware/evil_twin.py --i-understand-this-is-an-offline-lab-simulation-with-no-radio-emission \
  --simulate --lab-ssid lab-test-net \
  --pcap-out reports/flow.pcap --json reports/w2.json
```

### Run the rogue-AP detector against embedded beacon records

```bash
python3 firmware/evil_twin.py --detect
```

### Tests

```bash
python3 -m unittest discover -s tests
```

### Library usage

```python
from firmware.evil_twin import detect_rogue_aps, build_evil_twin_sequence
from firmware import frame_core as fc

seq = build_evil_twin_sequence("lab-test-net")
clones, fp_groups = detect_rogue_aps(beacon_list,
                                     known_bssids={"00:11:22:33:44:01"})
```

## Project Structure

- `firmware/evil_twin.py` — fingerprinting, detection, simulation, and config
  generation CLI.
- `firmware/frame_core.py` — 802.11 frame build/parse and pcap helpers.
- `tests/` — unit tests for the detection and simulation engines.

## Documentation

- [ETHICS.md](ETHICS.md) — Educational purpose and authorized use only.
- [SCOPE.md](SCOPE.md) — Authorized scope of research.
- [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md),
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Contributing

Contributions for educational and authorized wireless-security research are
welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT License — see [LICENSE](LICENSE) for details.

> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**