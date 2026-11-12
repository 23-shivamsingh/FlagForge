# Coverage and failure cases

| Scenario | Expected behavior | Caveat |
|---|---|---|
| Plain flag in a TCP segment | Direct match with stream/source evidence | Bad fragmentation or stream gaps can lose bytes |
| Base64 split over TCP packets | Join TCP segments by sequence and attempt decoding | Sequence wraparound and ambiguous overlap are limited |
| Base64 split over sequenced DNS subdomains | Join DNS labels by prefix indices and decode | Unrecognized sequences/encodings require manual interpretation |
| Multiple DNS TXT response fragments | Join TXT values and rescan | Heuristic concatenation can create false positives |
| HTTP chunked + gzip body | Dechunk, decompress, recursively scan | Incomplete HTTP bodies may fail |
| Embedded ZIP/image/PDF inside TCP | Carve known signatures and recursively inspect | Does not support every custom file wrapper |
| PCAPNG hidden text in comments | Inspect raw metadata/UTF-16 strings and decoders | Only limited transforms are explored |
| IP ID or ICMP data-channel | Reassemble low bytes or echo payload data in capture order | False positives and missing/duplicate packets possible |
| TLS SNI | Extract plaintext hostname | Does **not** decrypt encrypted application data |
| TLS application flag | Optional TShark with supplied valid SSLKEYLOGFILE | Keys and protocol compatibility essential |
| USB HID keyboard typed message | Optional TShark field decode and US keyboard report replay | Non-boot devices, missing reports and non-US layouts unsupported |
| Encrypted/custom cipher | Candidate hints / local AI reasoning | Not solvable generically without key, weakness, or challenge clues |
| False candidate | Mark as unverified and record provenance | **Only the scoreboard confirms correctness** |

## Known engineering limitations

- No authentication or multi-user isolation (loopback-only development server).
- In-memory jobs expire by access time; cleanup occurs on subsequent requests, not a guaranteed asynchronous timer.
- TShark, Zeek, EXIF tooling and Ollama are optional and require independent local installation.
- No full PCAP IPv4 fragment reassembly; only limited IPv6 support, no full QUIC/HTTP3 dissector built into Python.
- No automated exploit execution, active scanning, credential theft, dictionary attacks, full brute-force or CTF scoreboard access.
- No rigorous benchmark against public CTF challenge corpus; synthetic regressions demonstrate functions, not universal coverage.
