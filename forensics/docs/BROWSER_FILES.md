# Browser, SQLite, Archives and Unknown File Triaging

## Browser SQLite

Common browser sources: Chromium `History`, Firefox `places.sqlite`, download records, typed URLs and session stores. **The schema and timestamp convention depend on browser/version.** Check columns before assuming Unix epoch. Chromium commonly stores WebKit timestamps as microseconds since 1601, while SQLite may contain multiple time formats in one DB.

```bash
python3 -m nexsec_dfir classify History
python3 -m nexsec_dfir sqlite-inspect History
python3 -m nexsec_dfir sqlite-inspect History --table downloads --limit 30
```

The command works on a temporary copy of the SQLite DB and attempts to copy matching `History-wal` / `History-shm`. For a live browser profile, stop the writer or use a proper forensic snapshot before taking the source copy. Avoid reading/decrypting live credentials by accident.

## Archives / nested artifacts

```bash
python3 -m nexsec_dfir zip-inventory archive.zip
```

Check risky paths (`../`, absolute path), duplicates, symlink members, declared uncompressed sizes, compression ratios and encrypted flags. **Do not blindly extract a ZIP from untrusted evidence.** A metadata listing does not validate member CRC or password correctness.

## Header vs filename

```bash
python3 -m nexsec_dfir classify suspicious.bin
python3 -m nexsec_dfir hunt suspicious.bin
```

An `unknown` or `unidentified-binary` result means no recognized header; it does not prove encryption. Compressed Prefetch (`MAM\x04`) and Windows Registry (`regf`) can be detected by header, but require specialist decoders. Strings hunting reports offsets and encoding candidates only.

## Images and documents

- PNG: inspect chunk structure, metadata and appended data; bitplane techniques only when format fits.
- JPEG/GIF: image and EXIF analysis differ from PNG; avoid using PNG-specific stego tools indiscriminately.
- PDF/Office: use dedicated document structure/metadata tools; an OOXML document is ZIP-based but member content has different semantics.
- Audio: inspect file header, bit depth, channels, metadata and spectrogram before hypothesizing steganography.

Preserve any extracted material's SHA-256, extraction path and original source reference.
