"""Mocked external-tool tests plus synthetic source-integrity checks."""
import csv
import io
import json
import subprocess
import socket
import struct
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from nexsec_dfir.core import ForensicError, sha256_file
from nexsec_dfir.disk import analyze_disk
from nexsec_dfir.memory import analyze_memory
from nexsec_dfir.pcap import pcap_analyze
from nexsec_dfir.windows import analyze_windows
from nexsec_dfir.timeline import normalize_time, build_timeline
from nexsec_dfir.router import route
from nexsec_dfir.external import run_bounded
from nexsec_dfir.decoding import decode_value, inspect_email_urls
from nexsec_dfir.windows_exports import reconstruct_scriptblocks, inspect_registry_export
from nexsec_dfir.chunks import reassemble_chunks
from nexsec_dfir.vhd import convert_vhd
from nexsec_dfir.core import classify_file


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
        watched = self.root / "watch"
        watched.mkdir()
        result, truncated = run_bounded([__import__("sys").executable, "-c",
            "from pathlib import Path; import time; Path('" + str(watched / "dump.bin") + "').write_bytes(b'x'*1000000); time.sleep(5)"],
            timeout=10, max_output=1024, watch_directory=watched, max_directory_bytes=1024)
        self.assertTrue(truncated)

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
        with patch("nexsec_dfir.disk._run", return_value={"tool": "mmls", "output": "partition table"}) as run:
            result = analyze_disk(self.source, "partitions", sector_size=4096)
        self.assertEqual(result["sector_size_bytes"], 4096)
        self.assertEqual(run.call_args.args[1][:2], ["-b", "4096"])
        self.assertEqual(self.source.read_bytes(), b"synthetic immutable evidence")

    def test_tsk_filesystem_type_is_applied_to_stream_inventory(self):
        with patch("nexsec_dfir.disk._run", return_value={"tool": "fls", "output": "named stream"}) as run:
            analyze_disk(self.source, "files", offset=23, sector_size=4096, filesystem="ntfs")
        self.assertEqual(run.call_args.args[0], "fls")
        args = run.call_args.args[1]
        self.assertEqual(args[:6], ["-r", "-p", "-b", "4096", "-f", "ntfs"])
        self.assertEqual(args[6:8], ["-o", "23"])

    def test_tsk_fsstat_forwards_device_sector_size_and_sector_offset(self):
        with patch("nexsec_dfir.disk._run", return_value={"tool": "fsstat", "output": "filesystem"}) as run:
            analyze_disk(self.source, "filesystem", offset=31, sector_size=4096, filesystem="ntfs")
        self.assertEqual(run.call_args.args[0], "fsstat")
        self.assertEqual(run.call_args.args[1], ["-b", "4096", "-f", "ntfs", "-o", "31", str(self.source)])

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
        self.assertEqual(result["sha1"], hashlib.sha1(b"recovered").hexdigest())
        too_small = self.root / "reports" / "limited.bin"
        with patch("nexsec_dfir.disk.shutil.which", return_value="icat"), \
             patch("nexsec_dfir.disk.subprocess.Popen", FakeProc), \
             self.assertRaisesRegex(ForensicError, "exceeded"):
            analyze_disk(self.source, "extract", inode="42", output=too_small, max_bytes=2)
        self.assertFalse(too_small.exists())

    def test_ntfs_stream_extraction_uses_exact_metadata_address(self):
        captured = {}
        class FakeProc:
            def __init__(self, args, **_kwargs):
                captured["args"] = args
                self.stdout = io.BytesIO(b"named stream")
            def wait(self, timeout=None): return 0
            def kill(self): pass
        out = self.root / "case" / "stream.bin"
        with patch("nexsec_dfir.disk.shutil.which", return_value="icat"), \
             patch("nexsec_dfir.disk.subprocess.Popen", FakeProc):
            result = analyze_disk(self.source, "extract", offset=37, sector_size=4096, inode="42-128-5",
                                  filesystem="ntfs", output=out, max_bytes=100)
        self.assertEqual(captured["args"][-4:], ["-o", "37", str(self.source), "42-128-5"])
        self.assertLess(captured["args"].index("-b"), captured["args"].index("-o"))
        self.assertEqual(captured["args"][captured["args"].index("-b") + 1], "4096")
        self.assertEqual(captured["args"][captured["args"].index("-f") + 1], "ntfs")
        self.assertEqual(result["size_bytes"], len(b"named stream"))

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

    def test_base64_xor_and_utf16le_decode(self):
        text = "Write-Output 'offline'"
        plain = text.encode("utf-16le")
        key = b"key"
        encoded = bytes(value ^ key[index % len(key)] for index, value in enumerate(plain))
        value = base64.b64encode(encoded).decode()
        report, decoded = decode_value(value, from_base64=True, xor_key=key, text_encoding="utf-16le")
        self.assertEqual(decoded, plain)
        self.assertEqual(report["decoded_text"], text)
        with self.assertRaisesRegex(ForensicError, "Invalid Base64"):
            decode_value("%%%", from_base64=True)

    def test_email_url_query_decoding_is_offline(self):
        mail = self.root / "message.eml"
        token = base64.urlsafe_b64encode(b"https://example.invalid/path").decode().rstrip("=")
        mail.write_text(f"From: sender@example.invalid\nSubject: sample\nContent-Type: text/plain; charset=utf-8\n\nVisit https://example.invalid/?blob={token}\n")
        result = inspect_email_urls(mail, decode_param="blob")
        self.assertFalse(result["network_accessed"])
        self.assertEqual(result["urls"][0]["decoded_parameter_text"], "https://example.invalid/path")

    def test_email_integrity_detects_change_during_parse(self):
        mail = self.root / "message.eml"
        mail.write_text("Content-Type: text/plain\n\nhttps://example.invalid/\n")
        from nexsec_dfir import decoding
        original = decoding.evidence_identity
        def mutate(path):
            identity = original(path)
            path.write_text("changed")
            return identity
        with patch("nexsec_dfir.decoding.evidence_identity", side_effect=mutate), \
             self.assertRaisesRegex(ForensicError, "SHA-256 changed"):
            inspect_email_urls(mail)

    def test_scriptblock_reconstruction_and_registry_export_mapping(self):
        export = self.root / "events.csv"
        export.write_text("EventId,ScriptBlockId,MessageNumber,MessageTotal,ScriptBlockText,EventRecordId\n"
                          "4104,sb-1,2,2,second,8\n4104,sb-1,1,2,first,7\n")
        result = reconstruct_scriptblocks(export)
        block = result["script_blocks"][0]
        self.assertEqual(block["script_text"], "firstsecond")
        self.assertEqual([row["record_id"] for row in block["source_references"]], ["8", "7"])
        reg = self.root / "registry.csv"
        reg.write_text("KeyPath,ValueName,ValueData\nHKCU\\Software\\Run,Updater,powershell.exe -enc ABC\n")
        mapped = inspect_registry_export(reg, key_contains="software\\run", value_name="Updater")
        self.assertEqual(mapped["records"][0]["value_data"], "powershell.exe -enc ABC")

    def test_realistic_evtxecmd_payload_schema_and_record_provenance(self):
        fixture = Path(__file__).resolve().parent / "fixtures" / "evtxecmd-4104-synthetic.csv"
        result = reconstruct_scriptblocks(fixture)
        block = result["script_blocks"][0]
        self.assertEqual(block["status"], "complete")
        self.assertEqual(block["script_text"], "Set-Variable -Name sample -Value 1;Write-Output 'synthetic'")
        refs = block["source_references"]
        self.assertEqual([ref["record_id"] for ref in refs], ["701", "700"])
        self.assertTrue(all(ref["source_artifact"] == str(fixture.resolve()) for ref in refs))
        self.assertEqual(refs[0]["source_sha256"], sha256_file(fixture))
        self.assertEqual(refs[0]["timestamp_raw"], "2026-10-01 12:00:00.0000000")

    def test_scriptblock_reconstruction_rejects_unsupported_schema(self):
        export = self.root / "unsupported-evtxecmd.csv"
        export.write_text("EventRecordId,TimeCreated,EventId,Payload\n"
                          '9,2026-01-01T00:00:00Z,4104,"{\\"Unknown\\":\\"value\\"}"\n')
        with self.assertRaisesRegex(ForensicError, "Unsupported parser schema"):
            reconstruct_scriptblocks(export)

    def test_chunk_order_duplicate_hash_and_rejections(self):
        payload = b"hello world"
        rows = [
            {"job": "job-1", "part": 1, "total": 2, "data": base64.b64encode(b"world").decode(), "frame.number": "9", "tcp.stream": "2"},
            {"job": "job-1", "part": 0, "total": 2, "data": base64.b64encode(b"hello ").decode(), "frame.number": "4", "tcp.stream": "2"},
            {"job": "job-1", "part": 1, "total": 2, "data": base64.b64encode(b"world").decode(), "frame.number": "10", "tcp.stream": "2"},
        ]
        src = self.root / "evidence" / "chunks.jsonl"
        src.write_text("".join(json.dumps(row) + "\n" for row in rows))
        out = self.root / "case" / "assembled.bin"
        result = reassemble_chunks(src, out, expected_size=len(payload), expected_sha256=hashlib.sha256(payload).hexdigest())
        self.assertEqual(out.read_bytes(), payload)
        self.assertEqual(len(result["duplicate_parts"]), 1)
        self.assertEqual(result["part_references"][1][0]["frame_number"], "9")
        conflict = self.root / "evidence" / "conflict.jsonl"
        conflict.write_text("\n".join(json.dumps(row) for row in [rows[0], {**rows[0], "data": base64.b64encode(b"other").decode()}]) + "\n")
        with self.assertRaisesRegex(ForensicError, "Conflicting duplicate"):
            reassemble_chunks(conflict, self.root / "case" / "conflict.bin", job="job-1")
        missing = self.root / "evidence" / "missing.jsonl"
        missing.write_text(json.dumps(rows[0]) + "\n")
        with self.assertRaisesRegex(ForensicError, "Missing chunks"):
            reassemble_chunks(missing, self.root / "case" / "missing.bin", job="job-1")
        with self.assertRaisesRegex(ForensicError, "does not match"):
            reassemble_chunks(src, self.root / "case" / "bad-hash.bin", expected_sha256="0" * 64)
        self.assertFalse((self.root / "case" / "bad-hash.bin").exists())

    def test_chunk_nested_json_outer_fields_merge_without_conflict(self):
        content = b"payload"
        body = {"job": "job-a", "part": 0, "total": 1,
                "data": base64.b64encode(content).decode()}
        row = {"job": " job-a ", "part": "0", "total": "1",
               "data": base64.b64encode(content).decode().rstrip("="),
               "body": json.dumps(body), "frame.number": "17", "tcp.stream": "3"}
        source = self.root / "evidence" / "nested-chunk.jsonl"
        source.write_text(json.dumps(row) + "\n")
        output = self.root / "case" / "nested-payload.bin"
        result = reassemble_chunks(source, output, job="job-a")
        self.assertEqual(output.read_bytes(), content)
        self.assertEqual(result["part_references"][0][0]["frame_number"], "17")

    def test_chunk_nested_json_rejects_conflicting_outer_fields(self):
        encoded = base64.b64encode(b"payload").decode()
        inner = {"job": "job-a", "part": 0, "total": 1, "data": encoded}
        alternatives = {
            "job": "job-b",
            "part": 1,
            "total": 2,
            "data": base64.b64encode(b"different").decode(),
        }
        for field, value in alternatives.items():
            with self.subTest(field=field):
                row = {"body": json.dumps(inner), "job": "job-a", "part": 0,
                       "total": 1, "data": encoded, field: value}
                source = self.root / "evidence" / f"conflict-{field}.jsonl"
                source.write_text(json.dumps(row) + "\n")
                with self.assertRaisesRegex(ForensicError, f"Conflicting outer/body values for field {field}"):
                    reassemble_chunks(source, self.root / "case" / f"conflict-{field}.bin", job="job-a")

    def test_vhd_detection_and_qemu_unsupported_format(self):
        vhd = self.source.parent / "candidate.vhd"
        vhd.write_bytes(bytes(512) + b"conectix" + bytes(504))
        self.assertEqual(classify_file(vhd)["type"], "vhd")
        cp = subprocess.CompletedProcess([], 0, stdout=b'{"format":"raw","virtual-size":512}', stderr=b"")
        with patch("nexsec_dfir.vhd.shutil.which", return_value="qemu-img"), \
             patch("nexsec_dfir.vhd.run_bounded", return_value=(cp, False)), \
             self.assertRaisesRegex(ForensicError, "only VHD"):
            convert_vhd(vhd, self.root / "case" / "disk.raw")
        self.assertTrue(vhd.exists())

    def test_vhd_qemu_conversion_creates_hashed_separate_copy(self):
        vhd = self.root / "evidence" / "image.vhd"
        vhd.write_bytes(bytes(512) + b"conectix" + bytes(504))
        info = subprocess.CompletedProcess([], 0, stdout=b'{"format":"vpc","virtual-size":4}', stderr=b"")
        converted = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
        def fake_run(args, **_kwargs):
            if args[1] == "info":
                return info, False
            Path(args[-1]).write_bytes(b"raw!")
            return converted, False
        output = self.root / "case" / "image.raw"
        with patch("nexsec_dfir.vhd.shutil.which", return_value="qemu-img"), \
             patch("nexsec_dfir.vhd.run_bounded", side_effect=fake_run):
            report = convert_vhd(vhd, output, max_output_bytes=100)
        self.assertEqual(output.read_bytes(), b"raw!")
        self.assertEqual(report["output_sha256"], hashlib.sha256(b"raw!").hexdigest())
        self.assertEqual(vhd.stat().st_size, 1024)

    def test_vhd_explicit_larger_limit_and_destination_space_check(self):
        vhd = self.root / "evidence" / "large-image.vhd"
        vhd.write_bytes(bytes(512) + b"conectix" + bytes(504))
        virtual_size = 5_000_000_000
        info = subprocess.CompletedProcess([], 0,
            stdout=json.dumps({"format": "vpc", "virtual-size": virtual_size}).encode(), stderr=b"")
        converted = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
        def fake_run(args, **_kwargs):
            if args[1] == "info":
                return info, False
            Path(args[-1]).write_bytes(b"bounded mock output")
            return converted, False
        free = virtual_size + 128 * 1024 * 1024
        output = self.root / "case" / "large.raw"
        with patch("nexsec_dfir.vhd.shutil.which", return_value="qemu-img"), \
             patch("nexsec_dfir.vhd.run_bounded", side_effect=fake_run), \
             patch("nexsec_dfir.vhd.shutil.disk_usage", return_value=SimpleNamespace(free=free)):
            report = convert_vhd(vhd, output, max_output_bytes=6_000_000_000)
        self.assertEqual(report["virtual_size_bytes"], virtual_size)
        self.assertTrue(output.exists())

    def test_vhd_rejects_insufficient_space_before_conversion(self):
        vhd = self.root / "evidence" / "image.vhd"
        vhd.write_bytes(bytes(512) + b"conectix" + bytes(504))
        info = subprocess.CompletedProcess([], 0, stdout=b'{"format":"vpc","virtual-size":5000000000}', stderr=b"")
        output = self.root / "case" / "image.raw"
        with patch("nexsec_dfir.vhd.shutil.which", return_value="qemu-img"), \
             patch("nexsec_dfir.vhd.run_bounded", return_value=(info, False)) as run, \
             patch("nexsec_dfir.vhd.shutil.disk_usage", return_value=SimpleNamespace(free=4_000_000_000)), \
             self.assertRaisesRegex(ForensicError, "Insufficient free space"):
            convert_vhd(vhd, output, max_output_bytes=6_000_000_000)
        self.assertEqual(run.call_count, 1)
        self.assertFalse(output.exists())
        self.assertEqual(list((self.root / "case").glob("nexsec-vhd-*")), [])

    def test_vhd_failed_conversion_cleans_temporary_output(self):
        vhd = self.root / "evidence" / "image.vhd"
        vhd.write_bytes(bytes(512) + b"conectix" + bytes(504))
        info = subprocess.CompletedProcess([], 0, stdout=b'{"format":"vpc","virtual-size":4}', stderr=b"")
        failed = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"synthetic failure")
        def fake_run(args, **_kwargs):
            if args[1] == "info":
                return info, False
            Path(args[-1]).write_bytes(b"partial")
            return failed, False
        output = self.root / "case" / "image.raw"
        with patch("nexsec_dfir.vhd.shutil.which", return_value="qemu-img"), \
             patch("nexsec_dfir.vhd.run_bounded", side_effect=fake_run), \
             self.assertRaisesRegex(ForensicError, "conversion failed"):
            convert_vhd(vhd, output)
        self.assertFalse(output.exists())
        self.assertEqual(list((self.root / "case").glob("nexsec-vhd-*")), [])

    def test_vhd_removes_final_output_when_post_link_integrity_check_fails(self):
        vhd = self.root / "evidence" / "image.vhd"
        vhd.write_bytes(bytes(512) + b"conectix" + bytes(504))
        info = subprocess.CompletedProcess([], 0, stdout=b'{"format":"vpc","virtual-size":4}', stderr=b"")
        converted = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
        def fake_run(args, **_kwargs):
            if args[1] == "info":
                return info, False
            Path(args[-1]).write_bytes(b"raw!")
            return converted, False
        output = self.root / "case" / "image.raw"
        with patch("nexsec_dfir.vhd.shutil.which", return_value="qemu-img"), \
             patch("nexsec_dfir.vhd.run_bounded", side_effect=fake_run), \
             patch("nexsec_dfir.vhd.verify_source_unchanged", side_effect=[None, ForensicError("synthetic source change"), None]), \
             self.assertRaisesRegex(ForensicError, "synthetic source change"):
            convert_vhd(vhd, output)
        self.assertFalse(output.exists())

    @unittest.skipUnless(__import__("shutil").which("qemu-img"), "SKIPPED: qemu-img unavailable")
    def test_real_qemu_converts_synthetic_vhd(self):
        vhd = self.root / "evidence" / "real-tool.vhd"
        subprocess.run([__import__("shutil").which("qemu-img"), "create", "-f", "vpc", str(vhd), "1M"],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = self.root / "case" / "real-tool.raw"
        report = convert_vhd(vhd, output, max_output_bytes=2_000_000, timeout_seconds=30)
        self.assertEqual(report["input_format"], "vpc")
        self.assertGreater(output.stat().st_size, 0)
        self.assertEqual(report["output_sha256"], sha256_file(output))
        self.assertTrue(vhd.is_file())

    def test_volatility_dumpfiles_hashes_without_execution(self):
        version = subprocess.CompletedProcess([], 0, stdout=b"Volatility 3", stderr=b"")
        plugin = subprocess.CompletedProcess([], 0, stdout=b"[]", stderr=b"")
        def fake_run(args, **_kwargs):
            if args[-1] == "--version":
                return version, False
            tempdir = Path(args[args.index("-o") + 1])
            (tempdir / "tool-output.data").write_bytes(b"synthetic recovered bytes")
            return plugin, False
        dump_dir = self.root / "case" / "memory-dumps"
        with patch("nexsec_dfir.memory.shutil.which", return_value="vol"), \
             patch("nexsec_dfir.memory.run_bounded", side_effect=fake_run):
            report = analyze_memory(self.source, "windows-dumpfiles", dump_dir=dump_dir, max_dump_bytes=1024)
        dumped = report["dumped_files"][0]
        self.assertEqual(dumped["sha1"], hashlib.sha1(b"synthetic recovered bytes").hexdigest())
        self.assertEqual(Path(dumped["output_path"]).read_bytes(), b"synthetic recovered bytes")
        self.assertTrue(dump_dir.stat().st_mode & 0o700)

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
