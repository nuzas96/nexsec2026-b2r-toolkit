"""Synthetic positive/negative cases. No provided challenge evidence is used."""
import csv
import io
import json
import os
import subprocess
import sys
import sqlite3
import tempfile
import unittest
import warnings
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from nexsec_dfir.__main__ import validate_answer
from nexsec_dfir.archive import inventory_zip
from nexsec_dfir.csv_artifacts import inspect_csv
from nexsec_dfir.core import ForensicError, classify_file, create_case, sha256_file, verify_case, write_json
from nexsec_dfir.hunt import hunt_strings
from nexsec_dfir.ledger import record_finding, list_findings
from nexsec_dfir.pcap import pcap_summary
from nexsec_dfir.router import route
from nexsec_dfir.sqlite_artifacts import inspect_sqlite
from nexsec_dfir.timeline import build_timeline, normalize_time

RULES = Path(__file__).resolve().parent.parent / 'playbooks' / 'questions.json'

class WorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        self.case = self.root / 'case'

    def test_signature_positive_and_unknown_negative(self):
        signatures = {
            'evtx': b'ElfFile\x00' + b'\0' * 100,
            'registry-hive': b'regf' + b'\0' * 50,
            'compressed-prefetch-candidate': b'MAM\x04' + b'\0' * 50,
            'pcapng': b'\x0a\x0d\x0d\x0a' + b'\0' * 50,
            'sqlite': b'SQLite format 3\x00' + b'\0' * 50,
        }
        for expected, body in signatures.items():
            path = self.evidence / (expected + '.bin')
            path.write_bytes(body)
            self.assertEqual(classify_file(path)['type'], expected)
        unknown = self.evidence / 'mystery.raw'
        unknown.write_bytes(b'\x11\x22\x33' * 40)
        self.assertEqual(classify_file(unknown)['type'], 'unidentified-binary')
        self.assertEqual(classify_file(unknown)['confidence'], 'unknown')

    def test_preservation_and_change_detection(self):
        p = self.evidence / 'sample.bin'
        p.write_bytes(b'immutable-original')
        digest = sha256_file(p)
        case = create_case(self.evidence, self.case)
        self.assertEqual(case['artifacts'][0]['sha256'], digest)
        self.assertEqual(sha256_file(p), digest)
        self.assertTrue(verify_case(self.case)['passed'])
        p.write_bytes(b'ALTERED')
        result = verify_case(self.case)
        self.assertFalse(result['passed'])
        self.assertEqual(result['results'][0]['status'], 'CHANGED')

    def test_source_root_symlink_rejected(self):
        (self.evidence / 'real.txt').write_text('sample')
        link = self.root / 'evidence-link'
        link.symlink_to(self.evidence, target_is_directory=True)
        with self.assertRaisesRegex(ForensicError, 'symbolic link'):
            create_case(link, self.case)

    def test_no_overwrite_and_no_recursive_output(self):
        (self.evidence / 'x').write_text('a')
        with self.assertRaises(ForensicError):
            create_case(self.evidence, self.evidence / 'case')
        create_case(self.evidence, self.case)
        with self.assertRaises(ForensicError):
            create_case(self.evidence, self.case)

    def test_symlink_not_traversed(self):
        (self.evidence / 'inside.txt').write_text('in')
        (self.root / 'outside.txt').write_text('secret')
        (self.evidence / 'link').symlink_to(self.root / 'outside.txt')
        case = create_case(self.evidence, self.case)
        self.assertEqual([x['relative_path'] for x in case['artifacts']], ['inside.txt'])
        self.assertEqual(case['skipped_paths'][0]['reason'],'symlink-file-not-followed')

    def test_archive_metadata_flags_without_extraction(self):
        path = self.evidence / 'case.zip'
        with zipfile.ZipFile(path, 'w') as z:
            z.writestr('safe/note.txt', 'hello')
            z.writestr('../../escape.txt', 'do not extract')
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                z.writestr('safe/note.txt', 'duplicate')
        data = inventory_zip(path)
        self.assertEqual(data['entry_count'], 3)
        self.assertIn('parent-traversal', data['entries'][1]['flags'])
        self.assertIn('duplicate-name', data['entries'][2]['flags'])
        self.assertFalse((self.root / 'escape.txt').exists())

    def test_sqlite_read_on_copy(self):
        path = self.evidence / 'History'
        con = sqlite3.connect(path)
        con.execute('CREATE TABLE downloads (id INTEGER, url TEXT)')
        con.execute('INSERT INTO downloads VALUES (?, ?)', (9, 'https://example.test/file'))
        con.commit()
        con.close()
        original = sha256_file(path)
        result = inspect_sqlite(path, table='downloads', limit=2)
        self.assertEqual(result['sample_rows'][0]['url'], 'https://example.test/file')
        self.assertEqual(sha256_file(path), original)
        with self.assertRaises(ForensicError):
            inspect_sqlite(path, table='nosuchtable')

    def test_external_csv_inspection_and_malformed_headers(self):
        csvfile = self.evidence / 'evtx-export.csv'
        csvfile.write_text('TimeCreated,EventId,UserName\n2026-01-01T01:00Z,4624,alice\n2026-01-01T01:01Z,4625,bob\n2026-01-01T01:02Z,4624,alice\n')
        result = inspect_csv(csvfile,field='EventId',equals='4624',group_field='UserName',select='TimeCreated,UserName')
        self.assertEqual(result['matched_rows'], 2)
        self.assertEqual(result['group_counts'],[('alice',2)])
        self.assertEqual([row['source_row'] for row in result['selected_rows']], [2,4])
        with self.assertRaises(ForensicError):
            inspect_csv(csvfile,field='NoColumn',equals='4624')
        bad = self.evidence/'bad.csv'; bad.write_text('id,id\n1,2\n')
        with self.assertRaises(ForensicError):
            inspect_csv(bad)

    def test_hunt_offsets_and_cap(self):
        path = self.evidence / 'payload.bin'
        path.write_bytes(b'prefix\0https://example.test/payload\0' + 'cmd.exe'.encode('utf-16le'))
        out = hunt_strings(path)
        self.assertTrue(any('https://' in x['text_excerpt'] for x in out['hits']))
        self.assertTrue(any(x['encoding']=='utf-16le' for x in out['hits']))
        self.assertFalse(out['truncated'])
        out2 = hunt_strings(path, max_bytes=8)
        self.assertTrue(out2['truncated'])

    def test_timestamp_is_explicit_and_exact(self):
        dt = datetime(2026, 10, 26, 23, 6, 40, tzinfo=timezone.utc)
        filetime = int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10**7)
        webkit = int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10**6)
        self.assertEqual(normalize_time(str(filetime),'filetime_100ns',None)[0], '2026-10-26T23:06:40Z')
        self.assertEqual(normalize_time(str(webkit),'webkit_us',None)[0], '2026-10-26T23:06:40Z')
        self.assertEqual(normalize_time('2026-10-27 07:06:40','iso','Asia/Kuala_Lumpur')[0], '2026-10-26T23:06:40Z')
        with self.assertRaises(ValueError):
            normalize_time('2026-10-26 23:06:40','iso',None)
        with self.assertRaises(ValueError):
            normalize_time('26/10/2026 23:06:40','iso','UTC')

    def test_timeline_with_invalid_record_and_source_rows(self):
        csvp = self.evidence / 'prefetch.csv'
        csvp.write_text('time,event,ref\n2026-10-26T23:06:40Z,POWERSHELL,7\n2026-10-26T23:06:40Z,POWERSHELL,8\nbad-date,unknown,9\n')
        spec = {'sources':[{'path':str(csvp),'format':'csv','time_field':'time','event_field':'event','reference_field':'ref','name':'prefetch','time_encoding':'iso'}]}
        config = self.root / 'config.json';config.write_text(json.dumps(spec))
        out = self.root / 'timeline.csv'
        result = build_timeline(config,out)
        self.assertEqual(result['events'],2)
        self.assertEqual(result['unparsed_rows'],1)
        self.assertEqual(result['duplicates_for_review'],1)
        with out.open(newline='', encoding='utf-8') as fp:
            rows = list(csv.DictReader(fp))
        self.assertEqual(rows[0]['source_row'],'2')
        self.assertEqual(rows[1]['duplicate_of_prior'],'REVIEW')
        with self.assertRaises(ForensicError):
            build_timeline(config,out)

    def test_findings_ledger_requires_manifest_and_reference(self):
        p = self.evidence / 'log.evtx'; p.write_bytes(b'ElfFile\0' + b'\0'*100)
        create_case(self.evidence, self.case)
        item = record_finding(self.case, artifact='log.evtx', source_ref='Record ID 12',
                              observed='Event 4624 present', interpretation='Login reported',
                              confidence='supported-inference', question='Who logged on?')
        self.assertEqual(item['source_reference'], 'Record ID 12')
        self.assertEqual(item['artifact_sha256_at_intake'], sha256_file(p))
        self.assertEqual(len(list_findings(self.case)), 1)
        p.write_bytes(b'changed source')
        with self.assertRaisesRegex(ForensicError, 'original missing/modified'):
            record_finding(self.case, artifact='log.evtx', source_ref='Record 99', observed='changed',
                           interpretation='not trustworthy', confidence='hypothesis')
        with self.assertRaises(ForensicError):
            record_finding(self.case, artifact='does-not-exist', source_ref='record 1',
                           observed='oops', interpretation='unsupported',confidence='hypothesis')

    def test_report_refuses_overwrite(self):
        p = self.root / 'report.json'; p.write_text('ORIGINAL')
        with self.assertRaises(ForensicError):
            write_json(p, {'hello': 'world'})
        self.assertEqual(p.read_text(), 'ORIGINAL')

    def test_no_tshark_is_clear_failure(self):
        capture = self.evidence / 'sample.pcap'; capture.write_bytes(b'\xd4\xc3\xb2\xa1')
        with patch('nexsec_dfir.pcap.shutil.which', return_value=None):
            with self.assertRaisesRegex(ForensicError, 'tshark unavailable'):
                pcap_summary(capture)

    def test_tshark_mock_summary_counts(self):
        capture = self.evidence / 'sample.pcap'; capture.write_bytes(b'\xd4\xc3\xb2\xa1')
        from subprocess import CompletedProcess
        sample = '1\t1793056000\t10.0.0.1\t10.0.0.2\teth:ip:udp:dns\t\texample.test\t\t\n' \
                 '2\t1793056001\t10.0.0.1\t10.0.0.3\teth:ip:tcp:http\t7\t\texample.test\t/\n'
        with patch('nexsec_dfir.pcap.shutil.which', return_value='/usr/bin/tshark'), \
             patch('nexsec_dfir.pcap.subprocess.run', return_value=CompletedProcess([],0,stdout=sample,stderr='')) as mock_run:
            result = pcap_summary(capture)
        self.assertEqual(result['frames_processed'],2)
        self.assertEqual(result['dns_query_names'],[('example.test',1)])
        self.assertEqual(result['tcp_stream_counts'],[('7',1)])
        self.assertIn('-r',mock_run.call_args[0][0])

    def test_cli_timeline_write_once_without_json_overwrite(self):
        csvp = self.evidence / 'events.csv'
        csvp.write_text('time,event\n2026-10-26T23:06:40Z,execution\n')
        cfg = self.root / 'sources.json'
        cfg.write_text(json.dumps({'sources': [{'path': str(csvp), 'format': 'csv',
                     'time_field': 'time', 'event_field': 'event', 'time_encoding': 'iso'}]}))
        out = self.root / 'output.csv'
        completed = subprocess.run([sys.executable, '-m', 'nexsec_dfir', 'timeline-build',
                   '--manifest', str(cfg), '--output', str(out)],
                   cwd=str(Path(__file__).resolve().parent.parent), capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(out.read_text().startswith('timestamp_utc,'))
        self.assertIn('"events": 1', completed.stdout)

    def test_router_and_syntax_answer_check(self):
        suggestions = route('What is the last execution time from Prefetch?',RULES)['suggestions']
        self.assertEqual(suggestions[0]['id'],'WIN-EXEC')
        self.assertTrue(validate_answer('sha256','a'*64,'iso',None)['format_valid'])
        self.assertFalse(validate_answer('sha256','not-hash','iso',None)['format_valid'])
        self.assertFalse(validate_answer('ipv4','999.3.4.5','iso',None)['format_valid'])

if __name__ == '__main__':
    unittest.main()
