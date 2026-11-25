"""Mocked external-tool tests plus synthetic source-integrity checks."""
import csv
import io
import json
import subprocess
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nexsec_dfir.core import ForensicError, sha256_file
from nexsec_dfir.disk import analyze_disk
from nexsec_dfir.memory import analyze_memory
from nexsec_dfir.pcap import pcap_analyze
from nexsec_dfir.windows import analyze_windows
from nexsec_dfir.timeline import normalize_time, build_timeline
from nexsec_dfir.router import route
from nexsec_dfir.external import run_bounded


class AdvancedAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        evidence = self.root / "evidence"
        evidence.mkdir()
        self.source = evidence / "synthetic.raw"
        self.source.write_bytes(b"synthetic immutable evidence")

    def test_volatility_offline_json_and_traceability(self):
        cp = subprocess.CompletedProcess([], 0, stdout=b'[{"PID": 44}]', stderr=b"")
        version = subprocess.CompletedProcess([], 0, stdout=b"Volatility 3 2.28.0", stderr=b"")
        with patch("nexsec_dfir.memory.shutil.which", return_value="/usr/bin/vol"), \
             patch("nexsec_dfir.memory.run_bounded", side_effect=[(version, False), (cp, False)]) as run:
            result = analyze_memory(self.source, "windows-processes")
        args = run.call_args.args[0]
        self.assertIn("--offline", args)
        self.assertEqual(args[-1], "windows.pslist")
        self.assertEqual(result["records"], [{"PID": 44}])
        self.assertIn("2.28.0", result["tool_version"])
        self.assertEqual(result["source_sha256"], sha256_file(self.source))

    def test_volatility_symbol_error_and_timeout(self):
        cp = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"symbol table not found")
        version = subprocess.CompletedProcess([], 0, stdout=b"Volatility 3", stderr=b"")
        with patch("nexsec_dfir.memory.shutil.which", return_value="vol"), \
             patch("nexsec_dfir.memory.run_bounded", side_effect=[(version, False), (cp, False)]), \
             self.assertRaisesRegex(ForensicError, "symbol table unavailable"):
            analyze_memory(self.source, "windows-processes")
        with patch("nexsec_dfir.memory.shutil.which", return_value="vol"), \
             patch("nexsec_dfir.memory.run_bounded", side_effect=[(version, False), ForensicError("Subprocess timed out after 1s")]), \
             self.assertRaisesRegex(ForensicError, "timed out"):
            analyze_memory(self.source, "windows-processes")

    def test_subprocess_output_limit_is_enforced(self):
        result, truncated = run_bounded([__import__("sys").executable, "-c", "print('x' * 1000000)"],
                                        timeout=10, max_output=1024)
        self.assertTrue(truncated)
        self.assertLessEqual(len(result.stdout), 1024)
        with self.assertRaisesRegex(ForensicError, "timed out"):
            run_bounded([__import__("sys").executable, "-c", "import time; time.sleep(5)"],
                        timeout=0.1, max_output=1024)

    def test_missing_volatility_is_explicit(self):
        with patch("nexsec_dfir.memory.shutil.which", return_value=None), \
             self.assertRaisesRegex(ForensicError, "Volatility 3 unavailable"):
            analyze_memory(self.source, "windows-processes")

    def test_tshark_dns_fields_and_missing_tool(self):
        cp = subprocess.CompletedProcess([], 0, stdout=b'7\t1793056000\t10.0.0.1\t8.8.8.8\ta.test\t1.2.3.4\t\t0\n', stderr=b"")
        with patch("nexsec_dfir.pcap.shutil.which", return_value="tshark"), \
             patch("nexsec_dfir.pcap.run_bounded", return_value=(cp, False)):
            result = pcap_analyze(self.source, mode="dns")
        self.assertEqual(result["records"][0]["frame.number"], "7")
        self.assertIn("source_sha256", result)
        with patch("nexsec_dfir.pcap.shutil.which", return_value=None), \
             self.assertRaisesRegex(ForensicError, "tshark unavailable"):
            pcap_analyze(self.source, mode="dns")

    def test_tshark_detects_source_change(self):
        cp = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
        def mutate(*_args, **_kwargs):
            self.source.write_bytes(b"modified")
            return cp, False
        with patch("nexsec_dfir.pcap.shutil.which", return_value="tshark"), \
             patch("nexsec_dfir.pcap.run_bounded", side_effect=mutate), \
             self.assertRaisesRegex(ForensicError, "SHA-256 changed"):
            pcap_analyze(self.source, mode="dns")

    def test_tsk_read_only_listing_and_missing_tools(self):
        with patch("nexsec_dfir.disk._run", return_value={"tool": "mmls", "output": "partition table"}):
            result = analyze_disk(self.source, "partitions", sector_size=4096)
        self.assertEqual(result["sector_size_bytes"], 4096)
        self.assertEqual(self.source.read_bytes(), b"synthetic immutable evidence")

    @unittest.skipUnless(__import__("shutil").which("mmls"), "SKIPPED: mmls unavailable")
    def test_real_mmls_rejects_non_disk_synthetic_input(self):
        with self.assertRaisesRegex(ForensicError, "mmls exited"):
            analyze_disk(self.source, "partitions")
        self.assertEqual(self.source.read_bytes(), b"synthetic immutable evidence")

    def test_tsk_extract_output_limit_and_hash(self):
        class FakeProc:
            def __init__(self, *_args, **_kwargs):
                self.stdout = io.BytesIO(b"recovered")
            def wait(self, timeout=None): return 0
            def kill(self): pass
        out = self.root / "reports" / "recovered.bin"
        with patch("nexsec_dfir.disk.shutil.which", return_value="icat"), \
             patch("nexsec_dfir.disk.subprocess.Popen", FakeProc):
            result = analyze_disk(self.source, "extract", inode="42", output=out, max_bytes=100)
        self.assertEqual(out.read_bytes(), b"recovered")
        self.assertEqual(result["sha256"], __import__("hashlib").sha256(b"recovered").hexdigest())
        too_small = self.root / "reports" / "limited.bin"
        with patch("nexsec_dfir.disk.shutil.which", return_value="icat"), \
             patch("nexsec_dfir.disk.subprocess.Popen", FakeProc), \
             self.assertRaisesRegex(ForensicError, "exceeded"):
            analyze_disk(self.source, "extract", inode="42", output=too_small, max_bytes=2)
        self.assertFalse(too_small.exists())

    def test_windows_tool_is_platform_gated_and_parses_export(self):
        with patch("nexsec_dfir.windows.is_windows_host", return_value=False), \
             self.assertRaisesRegex(ForensicError, "require Windows"):
            analyze_windows(self.source, "evtx")
        def fake_run(args, **_kwargs):
            outdir = Path(args[-1])
            (outdir / "events.csv").write_text("EventRecordId,TimeCreated,EventId\n12,2026-01-02T03:04:05Z,4624\n")
            return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
        with patch("nexsec_dfir.windows.is_windows_host", return_value=True), \
             patch("nexsec_dfir.windows.shutil.which", return_value="EvtxECmd.exe"), \
             patch("nexsec_dfir.windows.subprocess.run", side_effect=fake_run):
            result = analyze_windows(self.source, "evtx")
        record = result["records"][0]
        self.assertEqual(record["record_id"], "12")
        self.assertEqual(record["timestamp_raw"], "2026-01-02T03:04:05Z")
        self.assertEqual(record["observed_value"]["EventId"], "4624")

    def test_route_has_requested_structured_fields(self):
        rules = Path(__file__).resolve().parents[1] / "playbooks" / "questions.json"
        result = route("Which IP uploaded the deleted file?", rules)
        self.assertTrue(result["suggestions"])
        row = result["suggestions"][0]
        for key in ("requested_information", "recommended_evidence_artifacts", "installed_tools_detected",
                    "suggested_workflow", "expected_output_fields", "possible_alternative_interpretations",
                    "verification_requirements", "troubleshooting_and_fallback"):
            self.assertIn(key, row)

    def test_timezone_ambiguity_and_jsonl_export_hash(self):
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            normalize_time("2026-11-01 01:30:00", "iso", "America/New_York")
        with self.assertRaisesRegex(ValueError, "Nonexistent"):
            normalize_time("2026-03-08 02:30:00", "iso", "America/New_York")
        events = self.root / "events.csv"
        events.write_text("time,event,id\n2026-01-01T00:00:00-05:00,login,9\n")
        spec = {"sources": [{"path": str(events), "format": "csv", "time_field": "time",
                             "event_field": "event", "reference_field": "id", "time_encoding": "iso"}]}
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps(spec))
        output = self.root / "timeline.jsonl"
        result = build_timeline(manifest, output)
        row = json.loads(output.read_text().splitlines()[0])
        self.assertEqual(row["timestamp_utc"], "2026-01-01T05:00:00Z")
        self.assertEqual(row["source_sha256"], sha256_file(events))
        self.assertEqual(row["source_reference"], "9")
        self.assertEqual(result["events"], 1)

    @unittest.skipUnless(__import__("shutil").which("tshark"), "SKIPPED: tshark unavailable")
    def test_real_tshark_synthetic_dns_capture(self):
        # One synthetic DNS query in classic PCAP, no public or challenge fixture.
        labels = b"".join(bytes([len(label)]) + label.encode() for label in ("a", "test")) + b"\0"
        dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)
        udp = struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0) + dns
        src, dst = socket.inet_aton("10.0.0.1"), socket.inet_aton("8.8.8.8")
        total = 20 + len(udp)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 17, 0, src, dst)
        frame = bytes.fromhex("00112233445566778899aabb0800") + ip + udp
        capture = self.root / "known-dns.pcap"
        with capture.open("wb") as fp:
            fp.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            fp.write(struct.pack("<IIII", 1793056000, 0, len(frame), len(frame)))
            fp.write(frame)
        result = pcap_analyze(capture, mode="dns", max_packets=10)
        self.assertEqual(result["records_returned"], 1)
        self.assertEqual(result["records"][0]["dns.qry.name"], "a.test")


if __name__ == "__main__":
    unittest.main()
