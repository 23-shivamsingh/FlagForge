# SECURITY / Threat model

FLAGFORGE is an offline CTF forensics utility that parses untrusted input files. It is designed as a **single-user localhost tool**, not as an internet-facing server.

## Controls already implemented

- Binds to `127.0.0.1` using `run.sh`.
- Host and Origin restrictions; security response headers.
- Upload size, archive depth, decompression size, number of extracted files, packets and decoder states capped.
- No `shell=True`, no arbitrary command input, no live network sniffing or outbound scan.
- File names sanitized for report and artifact naming; archive content processed in memory rather than extracting paths to disk.
- Optional CLI processes use argument arrays with timeouts and temporary working directories.
- Local Ollama endpoint is hardcoded to `http://127.0.0.1:11434`; model prompt treats source evidence as untrusted data.
- TLS key log is never copied into JSON reports or passed to AI; temporary key files are cleared and removed on normal execution.

## Residual risks

- Native libraries and third-party analyzers may contain vulnerabilities when processing malicious PCAP/files. Run hostile samples in a disposable VM/container with resource limits.
- The backend keeps full uploaded files in memory until the job is cleaned; any local process with sufficient privilege could inspect this memory.
- Optional external command errors/timeouts do not provide a full sandbox. No operating-system-level isolation is included.
- Some decoded strings or metadata may contain sensitive content. Reports and writeups may include those strings and candidate flags; review before sharing.
- The origin guard is not authentication. Do not publish this unauthenticated API to the internet or use an untrusted multi-user machine.
- `Ollama` is a separate locally running service. Do not use cloud-named model tags if you require strict local-only operation.

## For public hosting

Add authentication/authorization, isolated per-case containers, independent worker queues, CPU/RAM/disk/time quotas, content retention policies, malware scanning, audit logging and per-user access to artifacts. Prefer short-lived storage with explicit deletion controls. A static-only Vercel deployment cannot run the full Python and optional CLI pipeline.
