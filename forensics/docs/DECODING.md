# Offline Email, URL and Script Decoding

## Supported inputs and prerequisites

`email-urls` reads RFC822 `.eml` files with Python's standard library and extracts inert `http(s)` URL strings from text parts. It never fetches links. `decode-value` accepts a string or a bounded UTF-8 text file. Optional transforms are Base64, repeating-key XOR, and UTF-8/UTF-16LE/Latin-1 text decoding. No third-party tool is required.

## Usage

```bash
python3 -m nexsec_dfir email-urls suspicious.eml --decode-param token
python3 -m nexsec_dfir decode-value --value 'BASE64_TEXT' --base64 --text-encoding utf-16le
python3 -m nexsec_dfir decode-value --input-file encoded.txt --base64 \
  --xor-key-text 'KEY_DERIVED_FROM_EVIDENCE' --text-encoding utf-8 \
  --decoded-file /case/decoded.txt
python3 -m nexsec_dfir decode-value --value 'BASE64_TEXT' --base64 \
  --xor-key-hex '001122' --text-encoding utf-16le
```

Base64 input permits URL-safe alphabet, omitted padding and whitespace. Malformed characters/lengths fail. Repeating XOR keys must be non-empty. The decoded-file path must be new and separate from the source directory. `--output` stores the JSON report; it refuses overwrite.

## Expected output and verification

Email output contains headers, URL/host/path/query parameter names, source path and SHA-256, plus a bounded preview for the selected decoded query value. `decode-value` returns decoded text only when strict decoding succeeds, otherwise a hex preview and decode error; optional output files contain the full decoded bytes. Recompute hashes and compare the exact URL, Base64 and XOR transformations against the source. PowerShell `-EncodedCommand` content is commonly UTF-16LE after Base64 decoding; select the encoding explicitly.

## Error handling and limitations

Malformed Base64, empty XOR key, oversized/missing source and output collisions are explicit errors. URL extraction is regex-based and may miss obfuscated/HTML-escaped constructs beyond the standard parser handling. This module does not decode arbitrary encodings, recover mailbox attachments, execute scripts, or infer phishing/maliciousness from a URL. Never execute decoded scripts.
