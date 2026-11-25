# Chunked HTTP/JSON Payload Reconstruction

## Supported inputs and prerequisites

Consumes parsed CSV or JSONL records whose rows contain `job`, `part`, `total`, and Base64 `data`. Nested JSON can be selected with `--container-field`. Frame number and TCP stream are retained from parser rows. The module uses Python's standard library and does not parse packet bytes by itself.

## Usage

```bash
python3 -m nexsec_dfir chunks-reassemble http-records.jsonl \
  --reassembled-output /case/upload.bin --job JOB_ID \
  --expected-size 12345 --expected-sha256 EXPECTED_SHA256
```

Field names can be changed with `--job-field`, `--part-field`, `--total-field`, and `--data-field`. `--frame-field` and `--stream-field` select provenance fields. `--index-base 0` or `1` overrides index inference; absent an override, part 0 means zero-based, otherwise numbering is treated as one-based. `--max-bytes` (default 100 MB) and `--max-records` (default 500,000) bound work.

## Expected output

The binary output is written only after a complete set passes Base64 validation, duplicate checks, optional expected byte count, and optional SHA-256. JSON reports job ID, part count, detected index base, identical duplicate references, input parser-export path/hash, per-part frame/stream references, reconstructed size, and resulting SHA-256.

## Error handling and verification

Conflicting outer-row and nested-body values for `job`, `part`, `total`, or `data` fail explicitly instead of allowing one representation to overwrite the other. Equivalent integer and Base64 representations are compared by value. Conflicting duplicates, absent/missing chunks, out-of-range parts, inconsistent totals, malformed Base64, multiple jobs without `--job`, expected size/hash mismatch, source mutation and output collision fail without creating the reconstructed output. Verify the assembled file's reported hash and compare frame/stream references to the original capture. Identical repeated chunks are reported and counted once.

## Known limitations

The input must already be a parsed CSV/JSONL export; HTTP dechunking, decompression, multipart parsing and packet reconstruction are not performed here. A reconstructed object and an HTTP request do not by themselves prove successful exfiltration or remote receipt.
