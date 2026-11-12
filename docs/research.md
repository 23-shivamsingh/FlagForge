# Why FLAGFORGE exists — capability comparison (Nov 2026)

FLAGFORGE is not claiming its individual protocol handlers or decoders are novel. Its value is an **opinionated CTF answer workflow** that preserves reproducible source evidence.

| Established tool | Proven strengths | Gap addressed by FLAGFORGE | What FLAGFORGE does **not** replace |
|---|---|---|---|
| Wireshark / TShark | Protocol-aware dissection, following TCP, exporting HTTP/SMB/IMF/TFTP objects | Flag-pattern scans after reconstruction and decoder chains with the original challenge question | Robust implementation of all network protocol dissectors |
| NetworkMiner | Passive file, host, credential and media extraction from captures | Prioritizes challenge answers instead of presenting only inventory | Broad metadata extraction maturity |
| Zeek | Structured protocol logs, file-analysis framework | Automatically searches logs for CTF tokens and links logs back to case evidence | Traffic analytics, flexible policy scripts |
| CyberChef | Huge library of transformations and Magic detection, automatic suggestions | Starts with a PCAP, extracts likely bytes and runs bounded transformations without repeated manual copy/paste | Huge transformation library and arbitrary recipes |
| Claude / GPT / Codex | Open-ended reasoning about custom challenge narratives | Deterministic first pass with direct evidence; optional local AI integration | General reasoning power of cloud frontier models |

## Design choices

1. **Evidence first**: direct and decoded matches carry source names and transform chains; no claims of successful CTF submission.
2. **Question-aware**: natural-language intent prioritizes DNS, HTTP, streams, file transfer, metadata, USB and covert messages. It is a deterministic heuristic, not a promise of semantic understanding.
3. **Multi-layer**: native PCAP parsing remains available without TShark; optional Wireshark/Zeek processes deepen coverage when installed.
4. **Same screen**: input, answer desk, protocol ledger, decoder bench, file downloads, writeup and optional AI.
5. **Local-only by default**: no automatic capture uploads or cloud calls; binds loopback only.
6. **Bounded by design**: malformed captures, giant nested archives and expensive decoder branches get limits.

## Primary references

- Wireshark user guide — exporting objects: https://www.wireshark.org/docs/wsug_html_chunked/ChapterIntroduction.html and https://www.wireshark.org/docs/wsug_html_chunked/ChIOExportSection.html
- TShark manual and `--export-objects`: https://www.wireshark.org/docs/man-pages/tshark.html
- Zeek file-analysis logs: https://docs.zeek.org/en/current/reference/logs/files.html
- Zeek offline workflow: https://docs.zeek.org/en/current/quickstart.html
- NetworkMiner capability summary: https://forensics.wiki/networkminer/
- CyberChef Magic design: https://github.com/gchq/CyberChef/wiki/Automatic-detection-of-encoded-data-using-CyberChef-Magic
- Homebrew formula for CLI TShark: https://formulae.brew.sh/formula/wireshark
- Homebrew formula for Zeek: https://formulae.brew.sh/formula/zeek
- Ollama local deployment: https://ollama.com/download

**No benchmark superiority claim:** performance or solve-rate comparisons against these products have not been experimentally measured. No public benchmark was used to claim 100% PCAP solve rate. The repo tests use intentionally constructed, synthetic challenges.
