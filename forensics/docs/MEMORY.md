# Advanced Memory Forensics Playbook — Volatility 3

The workbench does **not** parse raw RAM internally. Use a compatible Volatility 3 installation. Symbols for a particular OS/build may be unavailable offline. A symbol lookup failure is not proof the dump has no artifacts.

## Windows memory sequence

```bash
# Use the installed Volatility 3 executable name on your analysis machine.
vol -f memory.raw windows.info
vol -f memory.raw windows.pslist
vol -f memory.raw windows.pstree
vol -f memory.raw windows.cmdline
vol -f memory.raw windows.netscan
vol -f memory.raw windows.malfind
```

Some plugins may be absent or renamed across Volatility versions; check `vol --help` and available plugin listings.

**Interpretation:**

1. Confirm the Windows build/profile and image type before trusting process output.
2. Compare parent/child links, process names, process creation/exit times and command lines. PID reuse can mislead attribution.
3. Compare connections (netscan) with process identities, plus separately provided host/PCAP logs when available.
4. Treat malfind suspicious pages as candidates only; benign JIT/runtime pages can produce similar patterns.
5. For specific injected binaries, compare memory offsets, VAD permissions, mapped files and extracted content hashes.
6. Record the plugin version, arguments, output record and symbol source; build a timeline using parser exports.

## Linux memory

Linux module/symbol support is version-sensitive. Validate actual kernel symbols before attempting Linux process/module plugins; do not reuse Windows plugin names. Memory can be partial, swapped, compressed or captured inconsistently.

## When stuck

- Wrong OS, unsupported crash dump vs raw image, corrupt acquisition or unsupported build can all prevent correct parsing.
- First determine whether symbols are present offline. Avoid assuming automatic downloads will work during a restricted exercise.
- Never run suspect binaries extracted from memory on the analysis host.

References:
- https://github.com/volatilityfoundation/volatility3
- https://volatility3.readthedocs.io/
