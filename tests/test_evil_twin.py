#!/usr/bin/env python3
"""Byte-exact unit tests for w2-evil-twin."""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from firmware import evil_twin as et
from firmware import frame_core as fc

SAFE_FLAG = et._SAFETY_FLAG


class SafetyGateTest(unittest.TestCase):
    def test_refuses_simulate_without_flag(self):
        rc = et.main(["--simulate"])
        self.assertEqual(rc, 2)

    def test_rejects_non_lab_ssid(self):
        rc = et.main([SAFE_FLAG, "--simulate", "--lab-ssid", "CorpNet-5G"])
        self.assertEqual(rc, 2)

    def test_accepts_confirmed_lab_simid(self):
        rc = et.main([SAFE_FLAG, "--simulate", "--lab-ssid", "lab-test-net",
                      "--json", os.path.join(tempfile.gettempdir(), "et.json")])
        self.assertEqual(rc, 0)


class BeaconCloneTest(unittest.TestCase):
    def test_rogue_beacon_has_cloned_ssid(self):
        seq = et.build_evil_twin_sequence("lab-test-net")
        rogue = [e for e in seq if e["phase"] == "beacon-rogue"][0]
        fields, _ies = fc.parse_beacon(rogue["data"][:-4])  # strip FCS
        self.assertEqual(fields["ssid"], "lab-test-net")
        self.assertEqual(fields["bssid"], "00:11:22:33:44:66")

    def test_beacon_roundtrips_byte_exact(self):
        seq = et.build_evil_twin_sequence("lab-test-net")
        rogue = [e for e in seq if e["phase"] == "beacon-rogue"][0]
        self.assertTrue(fc.verify_fcs(rogue["data"]))
        # parse without FCS and re-derive expected SSID
        fields, _ = fc.parse_beacon(rogue["data"][:-4])
        rebuilt = fc.build_beacon(fields["bssid"], ssid=fields["ssid"],
                                  timestamp=fields["timestamp"],
                                  beacon_interval=fields["beacon_interval"],
                                  seq_num=fields["seq_num"])
        self.assertEqual(rebuilt, rogue["data"][:-4])

    def test_deauth_on_capture_present(self):
        seq = et.build_evil_twin_sequence("lab-test-net")
        deauth = [e for e in seq if e["phase"] == "deauth-on-capture"][0]
        p = fc.parse_deauth(deauth["data"][:-4])
        self.assertEqual(p["reason_code"], 7)
        self.assertEqual(p["da"], "00:11:22:33:44:77")


class SequenceTest(unittest.TestCase):
    def test_ordering_is_deterministic(self):
        seq = et.build_evil_twin_sequence("lab-test-net")
        ordered = et.sort_sequence(seq)
        phases = [e["phase"] for e in ordered]
        self.assertEqual(phases, ["beacon-rogue", "beacon-legit", "probe-req",
                                  "probe-resp-rogue", "capture-beacon",
                                  "deauth-on-capture", "auth-req-rogue"])

    def test_all_frames_have_fcs(self):
        seq = et.build_evil_twin_sequence("lab-test-net")
        for e in seq:
            self.assertTrue(fc.verify_fcs(e["data"]), e["phase"])


class PcapFixtureTest(unittest.TestCase):
    def test_pcap_roundtrip_and_ordering(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "flow.pcap")
            seq = et.build_evil_twin_sequence("lab-test-net")
            n = et.write_capture_pcap(seq, path)
            self.assertEqual(n, len(seq))
            records = et.read_capture_pcap(path)
            kinds = [r["kind"] for r in records]
            self.assertIn("deauth", kinds)
            self.assertIn("beacon", kinds)
            issues = et.validate_capture_ordering(records)
            self.assertEqual(issues, [])


class RogueDetectionTest(unittest.TestCase):
    def test_rogue_twin_detected(self):
        clones, _ = et.detect_rogue_aps(et.SAMPLE_BEACONS, et.KNOWN_LEGITIMATE)
        rogues = [c for c in clones if c["is_clone"]]
        self.assertTrue(any("lab-corp-5g" == c["ssid"] for c in rogues))

    def test_legit_not_marked_rogue(self):
        clones, _ = et.detect_rogue_aps(et.SAMPLE_BEACONS, et.KNOWN_LEGITIMATE)
        legit = [c for c in clones if not c["is_clone"]]
        for c in legit:
            self.assertIn(c["bssid"], et.KNOWN_LEGITIMATE)


class ReportTest(unittest.TestCase):
    def test_json_serializable(self):
        r = et.run_simulation("lab-test-net", "reports")
        json.dumps(r, default=str)

    def test_demo_exit_zero(self):
        self.assertEqual(et.run_demo(), 0)


if __name__ == "__main__":
    unittest.main()
