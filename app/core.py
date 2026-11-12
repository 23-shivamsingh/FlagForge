"""CTF file analysis engine. Purely passive, bounded, no outbound network calls."""
from __future__ import annotations
import hashlib
import io
import json
import mimetypes
import os
import re
import shutil
import struct
import subprocess
import tarfile
import wave
import zipfile
from pathlib import Path
from typing import Any

from .decoders import MAX_TEXT, decode_hunt, decompress_known, extract_flags, flag_regex, legibility, sample_text
from .pcap import parse_capture
from .advanced_pcap import dns_reconstructions, tls_sni, recover_hid_keystrokes, investigation_plan, rank_flags

MAX_NESTED_DEPTH = 2
MAX_SCAN_BYTES = 2_500_000
MAX_ARCHIVE_TOTAL = 12_000_000
MAX_ARCHIVE_ENTRIES = 100
MAX_ARTIFACTS = 60
MAX_ARTIFACT_BYTES = 3_000_000

TOOLS = ['tshark', 'zeek', 'exiftool', 'binwalk', 'steghide', 'zsteg', '7z', '7zz', 'ffprobe', 'ffmpeg', 'pdftotext', 'tesseract', 'zbarimg']


def tool_status():
    return [{'name': x, 'available': bool(shutil.which(x))} for x in TOOLS]


def kind_of(name: str, data: bytes):
    ext = Path(name).suffix.lower()
    if data.startswith((b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a')):
        return 'PCAP / PCAPNG'
    if data.startswith(b'\x89PNG\r\n\x1a\n'): return 'PNG image'
    if data.startswith(b'\xff\xd8\xff'): return 'JPEG image'
    if data.startswith(b'GIF8'): return 'GIF image'
    if data.startswith(b'BM'): return 'BMP image'
    if data.startswith(b'PK\x03\x04') or zipfile.is_zipfile(io.BytesIO(data)): return 'ZIP archive'
    if data.startswith(b'%PDF-'): return 'PDF document'
    if data.startswith(b'RIFF') and data[8:12] == b'WAVE': return 'WAV audio'
    if data.startswith(b'ID3') or (len(data) >= 2 and data[:2] == b'\xff\xfb'): return 'MP3 audio'
    if data.startswith(b'\x1f\x8b'): return 'GZIP archive'
    if data.startswith(b'7z\xbc\xaf\x27\x1c'): return '7z archive'
    if len(data) > 262 and data[257:262] == b'ustar': return 'TAR archive'
    if ext in ('.txt', '.csv', '.log', '.json', '.xml', '.html', '.md', '.js', '.py') or legibility(data[:8000]) > .90:
        return 'Text / source'
    return 'Binary / unknown'


def get_strings(blob, minimum=6, limit=65):
    patterns = [rb'[\x20-\x7e]{' + str(minimum).encode() + rb',}',
                rb'(?:[\x20-\x7e]\x00){' + str(minimum).encode() + rb',}']
    values = []
    for i, pat in enumerate(patterns):
        for match in re.finditer(pat, blob[:MAX_SCAN_BYTES]):
            part = match.group()[:260]
            if i: part = part.replace(b'\x00', b'')
            entry = part.decode('latin-1', 'replace')
            if entry not in values:
                values.append(entry)
            if len(values) >= limit:
                return values
    return values


def invoke(program: str, args: list[str], timeout=6, limit=8000):
    if not shutil.which(program):
        return None
    try:
        p = subprocess.run([program] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, check=False, stdin=subprocess.DEVNULL, shell=False)
        output = (p.stdout + b'\n' + p.stderr)[:limit].decode('utf-8', 'replace').strip()
        return output
    except (OSError, subprocess.TimeoutExpired):
        return None


class Inspector:
    def __init__(self, prefix='', tls_keylog=None, question=''):
        self.pattern = flag_regex(prefix)
        self.prefix = prefix
        self.question = question[:1200]
        self.tls_keylog = tls_keylog
        self.flags = []
        self.decodes = []
        self.artifacts: dict[str, bytes] = {}
        self.artifact_info = []
        self.files = []
        self.evidence = []
        self.hints = []
        self.pcap = None
        self.metadata: dict[str, Any] = {}
        self._seen_flags = set()
        self._visited = set()
        self.archive_budget = MAX_ARCHIVE_TOTAL

    def add_evidence(self, message: str):
        if len(self.evidence) < 80 and message not in self.evidence:
            self.evidence.append(message[:500])

    def add_artifact(self, label: str, content: bytes, source='extracted'):
        if not content or len(content) > MAX_ARTIFACT_BYTES or len(self.artifacts) >= MAX_ARTIFACTS:
            return None
        uid = f'a{len(self.artifacts) + 1:03d}'
        self.artifacts[uid] = content
        self.artifact_info.append({'id': uid, 'name': Path(label).name[:100], 'size': len(content),
                                   'source': source, 'sha256': hashlib.sha256(content).hexdigest()})
        return uid

    def scan_bytes(self, blob, origin, decode=True):
        for value in extract_flags(blob[:MAX_SCAN_BYTES], self.pattern):
            self.record_flag(value, origin, [], 'direct')
        # UTF-16 text is common in filenames, metadata, exported Windows captures.
        # Try both endiannesses only when NUL-separated text is plausible.
        head = blob[:min(len(blob), 160_000)]
        if len(head) > 12 and head.count(b'\x00') >= len(head)//8:
            for encoding in ('utf-16le', 'utf-16be'):
                readable = head.decode(encoding, 'ignore')
                for value in extract_flags(readable, self.pattern):
                    self.record_flag(value, origin + ' / ' + encoding, [encoding], 'decoded')
        if decode and len(blob) <= MAX_SCAN_BYTES:
            # Decode the most relevant regions, never run huge brute force across an entire PCAP.
            for item in self.find_encoded(blob):
                findings, trails = decode_hunt(item, self.pattern, max_depth=2)
                for finding in findings:
                    self.record_flag(finding['value'], origin, finding['chain'], 'decoded')
                for trail in trails:
                    if len(self.decodes) < 80 and trail['preview'].strip():
                        self.decodes.append({'source': origin, **trail})

    def find_encoded(self, data: bytes):
        regions = []
        if len(data) < 8192:
            regions.append(data)
        printable = re.findall(rb'[\x20-\x7e]{12,2048}', data[:MAX_SCAN_BYTES])
        for span in printable[:20]:
            if re.search(rb'(?:[A-Za-z0-9+/]{16,}={0,2}|[a-fA-F0-9]{20,}|%[a-fA-F0-9]{2}|[01]{24,})', span):
                regions.append(span)
        return regions[:22]

    def record_flag(self, value, source, chain, method):
        if value in self._seen_flags:
            existing = next(f for f in self.flags if f['value'] == value)
            if source not in existing['sources'] and len(existing['sources']) < 10:
                existing['sources'].append(source)
            if existing['method'] != 'direct' and method == 'direct':
                existing.update({'source': source, 'method': 'direct', 'chain': [], 'confidence': 'High'})
            return
        if len(self.flags) >= 100:
            return
        self._seen_flags.add(value)
        self.flags.append({'value': value, 'source': source, 'sources': [source],
                           'method': method, 'chain': chain,
                           'confidence': 'High' if method == 'direct' else 'Medium',
                           'verified': False})

    def inspect(self, name, data, depth=0, source='upload'):
        if depth > MAX_NESTED_DEPTH or len(self.files) > 100:
            return
        fingerprint = hashlib.sha256(data).digest()
        if fingerprint in self._visited: return
        self._visited.add(fingerprint)
        kind = kind_of(name, data)
        self.files.append({'name': Path(name).name[:120], 'kind': kind, 'size': len(data), 'depth': depth, 'source': source})
        self.scan_bytes(data, name, decode=(kind != 'PCAP / PCAPNG'))
        if depth == 0:
            self.metadata = {'filename': name, 'kind': kind, 'size': len(data),
                             'sha256': hashlib.sha256(data).hexdigest(),
                             'sha1': hashlib.sha1(data).hexdigest(),
                             'md5': hashlib.md5(data).hexdigest(),
                             'preview_hex': data[:80].hex(' '),
                             'strings': get_strings(data)}
        if kind == 'PCAP / PCAPNG':
            # PCAPNG option comments, interface descriptions and custom blocks may
            # contain encoded metadata that is not part of an IP payload.
            strings = get_strings(data, minimum=10, limit=90)
            if strings:
                self.scan_bytes('\n'.join(strings).encode('utf-8', 'replace'),
                                name + ' / capture metadata strings')
            self.inspect_pcap(data)
        if kind == 'ZIP archive':
            self.inspect_zip(name, data, depth)
        if kind == 'TAR archive':
            self.inspect_tar(name, data, depth)
        if kind == 'GZIP archive':
            decompressed = decompress_known(data)
            if decompressed and depth < MAX_NESTED_DEPTH:
                method, out = decompressed
                self.add_artifact(f'{Path(name).stem}-decompressed.bin', out, method)
                self.inspect(name + ' (decompressed)', out, depth + 1, method)
        if kind in ('PNG image', 'BMP image', 'JPEG image', 'GIF image'):
            self.inspect_image(name, data)
        if kind == 'WAV audio':
            self.inspect_wave(name, data)
        if kind == 'MP3 audio':
            self.inspect_mp3(name, data)
        if kind == 'PDF document':
            self.inspect_pdf(name, data)
        if depth == 0:
            self.inspect_external(name, data, kind)
            self.inspect_carving(name, data, kind)
        if kind == '7z archive' and depth == 0:
            self.hints.append('7z detected. Use the installed 7z/7zz CLI for password-protected archive extraction.')

    def inspect_pcap(self, data):
        try:
            cap = parse_capture(data)
            tls_hosts = []
            for name, raw in cap.pop('_stream_blobs'):
                if raw:
                    for hostname in tls_sni(raw):
                        tls_hosts.append(hostname)
                        self.scan_bytes(hostname.encode(), f'TLS SNI / {name}')
                    artifact_id = self.add_artifact(name, raw, 'TCP reconstructed stream')
                    for s in cap['streams']:
                        if f'tcp-stream-{s["id"] + 1:02d}.bin' == name:
                            s['artifact_id'] = artifact_id
                    self.scan_bytes(raw, name)
                    self.inspect_stream_carving(name, raw)
            cap['covert'] = []
            for label, fragments in cap.pop('_icmp_series', []):
                # ICMP echo data split between messages, grouped per direction.
                if len(fragments) < 2: continue
                payload = b''.join(fragments)[:MAX_SCAN_BYTES]
                if not payload: continue
                source_label = 'ICMP echo concatenation / ' + label
                self.scan_bytes(payload, source_label)
                cap['covert'].append({'source': source_label, 'frames': len(fragments),
                                      'preview': payload[:180].decode('latin-1', 'replace')})
                self.add_artifact('icmp-echo-concatenated.bin', payload, source_label)
            for label, identifiers in cap.pop('_ipid_series', []):
                # Low-byte ID encoding is common in intentionally created CTF PCAPs.
                if len(identifiers) < 6: continue
                raw = bytes(x & 0xff for x in identifiers)
                if sum(32 <= c < 127 for c in raw) / len(raw) < .75: continue
                source_label = 'IPv4 identification low-byte hypothesis / ' + label
                self.scan_bytes(raw, source_label)
                cap['covert'].append({'source': source_label, 'frames': len(identifiers),
                                      'preview': raw[:180].decode('latin-1', 'replace')})
            for name, raw in cap.pop('_extracted'):
                if raw:
                    self.add_artifact(name, raw, 'HTTP body')
                    self.inspect(name, raw, 1, 'HTTP body')
            cap['tls'] = [{'sni': s} for s in dict.fromkeys(tls_hosts)][:20]
            if tls_hosts:
                self.add_evidence('Recovered cleartext TLS ClientHello SNI hostname(s), not encrypted application data.')
            for event in cap['dns']:
                self.scan_bytes((event.get('name', '') + ' ' + event.get('value', '')).encode(), 'DNS query / TXT')
            cap['dns_reassembled'] = []
            for source_label, reconstructed in dns_reconstructions(cap['dns']):
                cap['dns_reassembled'].append({'source': source_label, 'length': len(reconstructed),
                                               'preview': reconstructed[:220].decode('latin-1', 'replace')})
                self.scan_bytes(reconstructed, source_label)
                if len(reconstructed) < MAX_ARTIFACT_BYTES:
                    self.add_artifact('dns-reassembled-' + str(len(cap['dns_reassembled'])) + '.bin', reconstructed, source_label)
            if cap['dns_reassembled']:
                self.add_evidence('Reassembled DNS label/TXT data into ' + str(len(cap['dns_reassembled'])) + ' encoded payload candidate(s).')
            for sample in cap['udp_samples']:
                self.scan_bytes(sample['preview'].encode('latin-1', 'replace'), 'UDP payload')
            for sample in cap['payload_samples']:
                self.scan_bytes(sample['preview'].encode('latin-1', 'replace'), 'ICMP / IP payload')
            self.inspect_tshark(data)
            self.inspect_zeek(data, cap)
            self.pcap = cap
            self.add_evidence(f'Parsed {cap["packets"]} packets, {len(cap["streams"])} directional TCP streams, {len(cap["dns"])} DNS records.')
            if cap['http']: self.add_evidence(f'Found {len(cap["http"])} HTTP requests/responses in plaintext TCP.')
            if any(x['name'] == 'TCP' for x in cap['protocols']):
                self.hints.append('Inspect TCP streams and recovered HTTP bodies; flags can be fragmented across packets.')
            self.hints.append('TLS/HTTPS payloads require legitimate session keys for decryption; this app does not bypass encryption.')
        except (ValueError, OSError, OverflowError, IndexError, struct.error):
            self.hints.append('Could not fully parse capture; verify PCAP/PCAPNG integrity or try TShark.')

    def inspect_zip(self, name, data, depth):
        if depth >= MAX_NESTED_DEPTH: return
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                entries = archive.infolist()[:MAX_ARCHIVE_ENTRIES]
                self.add_evidence(f'ZIP archive lists {len(archive.infolist())} entries; inspecting up to {MAX_ARCHIVE_ENTRIES}.')
                for item in entries:
                    if item.is_dir(): continue
                    if item.flag_bits & 1:
                        self.hints.append(f'Encrypted ZIP entry: {Path(item.filename).name}; password required.')
                        continue
                    if item.file_size > 2_000_000 or item.file_size > self.archive_budget: continue
                    try:
                        with archive.open(item) as infile:
                            raw = infile.read(min(item.file_size + 1, 2_000_001))
                        if len(raw) > item.file_size or len(raw) > 2_000_000: continue
                        self.archive_budget -= len(raw)
                        safe_name = Path(item.filename).name or 'unnamed'
                        self.add_artifact(safe_name, raw, f'ZIP entry {item.filename[:80]}')
                        self.inspect(safe_name, raw, depth + 1, 'ZIP entry')
                    except (RuntimeError, ValueError, EOFError, OSError, zipfile.BadZipFile):
                        self.hints.append(f'Could not decode ZIP entry: {Path(item.filename).name}')
        except (zipfile.BadZipFile, OSError, ValueError):
            self.hints.append('ZIP appears malformed or unreadable.')

    def inspect_tar(self, name, data, depth):
        if depth >= MAX_NESTED_DEPTH: return
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
                for item in archive.getmembers()[:MAX_ARCHIVE_ENTRIES]:
                    if not item.isfile() or item.size > 2_000_000 or item.size > self.archive_budget: continue
                    stream = archive.extractfile(item)
                    if not stream: continue
                    raw = stream.read(item.size + 1)
                    if len(raw) > item.size: continue
                    self.archive_budget -= len(raw)
                    safe_name = Path(item.name).name or 'unnamed'
                    self.add_artifact(safe_name, raw, 'TAR entry')
                    self.inspect(safe_name, raw, depth + 1, 'TAR entry')
        except (tarfile.TarError, OSError, ValueError):
            self.hints.append('TAR appears malformed or unreadable.')

    def inspect_image(self, name, data):
        try:
            from PIL import Image, ExifTags
            Image.MAX_IMAGE_PIXELS = 16_000_000
            with Image.open(io.BytesIO(data)) as im:
                self.add_evidence(f'Image: {im.format}, {im.width}×{im.height}, {im.mode}.')
                info = {str(k): str(v)[:250] for k, v in im.info.items() if isinstance(v, (str, int, float))}
                if info:
                    self.add_evidence('Image metadata: ' + json.dumps(info, ensure_ascii=True)[:450])
                    self.scan_bytes(json.dumps(info).encode(), f'{name} metadata')
                exif = im.getexif()
                if exif:
                    formatted = {str(ExifTags.TAGS.get(k, k)): str(v)[:250] for k, v in exif.items()}
                    self.scan_bytes(json.dumps(formatted).encode(), f'{name} EXIF')
                if im.width * im.height > 2_500_000:
                    self.hints.append('Image too large for fast LSB analysis; metadata and raw bytes still scanned.')
                    return
                mode = 'RGBA' if 'A' in im.getbands() else 'RGB'
                raw_pixels = im.convert(mode).tobytes()
                stride = len(mode)
                count = min(im.width * im.height, 500_000)
                for idx, channel in enumerate(mode):
                    for bit in (0, 1):
                        for order in ('MSB', 'LSB'):
                            bits = ((raw_pixels[p * stride + idx] >> bit) & 1 for p in range(count))
                            packed = self.pack_bits(bits, lsb_first=order == 'LSB')
                            self.scan_bytes(packed, f'{name} / {channel} bit {bit}, {order} order', decode=False)
                packed = self.pack_bits((v & 1 for v in raw_pixels[:count * stride]))
                self.scan_bytes(packed, f'{name} / {mode} interleaved LSB', decode=False)
                self.add_evidence('Completed channel-wise and interleaved LSB bit-plane checks.')
                self.hints.append('Image LSB checks are heuristic, not equivalent to exhaustive stegsolve/zsteg.')
        except (OSError, ValueError, ImportError, MemoryError):
            self.hints.append('Image decoder could not inspect pixel data.')

    @staticmethod
    def pack_bits(bits, lsb_first=False):
        out = bytearray()
        value = 0
        i = 0
        for x in bits:
            if lsb_first:
                value |= x << i
            else:
                value = (value << 1) | x
            i += 1
            if i == 8:
                out.append(value)
                value = i = 0
        return bytes(out)

    def inspect_wave(self, name, data):
        try:
            with wave.open(io.BytesIO(data), 'rb') as audio:
                self.add_evidence(f'WAV: {audio.getnchannels()} channels, {audio.getframerate()} Hz, {audio.getsampwidth() * 8} bits/sample.')
                samples = audio.readframes(min(audio.getnframes(), 250_000))
                for bit in (0, 1):
                    packed = self.pack_bits(((b >> bit) & 1 for b in samples))
                    self.scan_bytes(packed, f'{name} / PCM bit-plane {bit}', decode=False)
        except (wave.Error, EOFError):
            self.hints.append('WAV decoding failed or compression unsupported.')

    def inspect_pdf(self, name, data):
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(data), strict=False)
            self.add_evidence(f'PDF has {len(reader.pages)} pages.')
            for index, page in enumerate(reader.pages[:40]):
                content = (page.extract_text() or '')[:100_000].encode()
                self.scan_bytes(content, f'{name} page {index + 1}')
                if content:
                    self.add_artifact(f'pdf-page-{index + 1}.txt', content, 'PDF text extraction')
        except Exception as exc:
            self.hints.append(f'PDF parsing could not complete: {type(exc).__name__}.')

    def inspect_mp3(self, name, data):
        if not shutil.which('ffmpeg'):
            self.hints.append('Install ffmpeg for compressed audio sample inspection.')
            return
        import tempfile
        with tempfile.TemporaryDirectory(prefix='flagforge-audio-') as tmp:
            path = Path(tmp) / 'audio.mp3'
            path.write_bytes(data)
            try:
                run = subprocess.run(['ffmpeg', '-nostdin', '-v', 'error', '-i', str(path),
                                      '-t', '15', '-ac', '1', '-ar', '11025',
                                      '-f', 'wav', '-'], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=12, check=False)
                if run.returncode == 0 and 44 < len(run.stdout) <= MAX_ARTIFACT_BYTES:
                    self.inspect_wave(name + ' decoded WAV', run.stdout)
            except (OSError, subprocess.TimeoutExpired):
                self.hints.append('Audio conversion timed out or is unavailable.')

    def inspect_carving(self, name, data, kind):
        """Look for file polyglots / appended ZIP and payloads after image end markers."""
        if len(data) < 24:
            return
        offset = None
        if kind == 'PNG image':
            i = 8
            while i + 12 <= len(data):
                length = int.from_bytes(data[i:i + 4], 'big')
                if length > len(data) - i - 12:
                    break
                chunk_type = data[i + 4:i + 8]
                i += length + 12
                if chunk_type == b'IEND':
                    offset = i
                    break
        elif kind == 'JPEG image':
            end = data.find(b'\xff\xd9', 2)
            if end >= 0:
                offset = end + 2
        if offset is not None and len(data) - offset > 8:
            tail = data[offset:]
            self.add_evidence(f'Detected {len(tail)} appended bytes after the {kind} end marker.')
            self.add_artifact('appended-payload.bin', tail, 'image trailer')
            self.inspect(name + ' appended data', tail, 1, 'image trailer')
        for m in list(re.finditer(rb'PK\x03\x04', data[:MAX_SCAN_BYTES]))[:4]:
            at = m.start()
            if at == 0 or (offset is not None and at >= offset):
                continue
            tail = data[at:]
            if zipfile.is_zipfile(io.BytesIO(tail)):
                self.add_evidence(f'ZIP file signature found at offset 0x{at:x}.')
                self.add_artifact('embedded-archive.zip', tail, 'signature carving')
                self.inspect(name + ' embedded.zip', tail, 1, 'carved ZIP')

    def inspect_stream_carving(self, name: str, stream: bytes):
        """Extract recognizable embedded documents from arbitrary directional streams.

        Conservative byte signatures, bounded size and recursion. A MIME type alone
        is not trusted, and nothing extracted is executed.
        """
        signature_map = ((b'PK\x03\x04', 'zip'), (b'\x89PNG\r\n\x1a\n', 'png'),
                         (b'\xff\xd8\xff', 'jpg'), (b'%PDF-', 'pdf'),
                         (b'\x1f\x8b\x08', 'gz'), (b'GIF8', 'gif'))
        positions = []
        for marker, ext in signature_map:
            pos = stream.find(marker)
            if pos >= 0:
                positions.append((pos, ext))
        for pos, ext in sorted(positions)[:4]:
            payload = stream[pos:pos + MAX_ARTIFACT_BYTES]
            if ext == 'zip' and not zipfile.is_zipfile(io.BytesIO(payload)):
                continue
            if ext == 'png':
                end = payload.find(b'IEND')
                if end < 0: continue
                payload = payload[:end + 8]  # IEND + CRC
            if ext == 'jpg':
                end = payload.find(b'\xff\xd9', 2)
                if end < 0: continue
                payload = payload[:end+2]
            if ext == 'pdf':
                end = payload.find(b'%%EOF')
                if end >= 0: payload = payload[:end + 5]
            if not payload or len(payload) > MAX_ARTIFACT_BYTES:
                continue
            label = f'carved-stream-{len(self.artifacts)+1:03d}.{ext}'
            artifact = self.add_artifact(label, payload, f'{name} @ 0x{pos:x}')
            if artifact:
                self.add_evidence(f'Carved embedded {ext.upper()} file at offset 0x{pos:x} from {name}.')
                self.inspect(label, payload, 1, 'TCP stream carving')

    def inspect_tshark(self, data):
        """Optional installed TShark: export protocol objects and decode USB boot keyboard reports."""
        if not shutil.which('tshark'):
            if self.tls_keylog:
                self.hints.append('TLS key log supplied but TShark is absent; no decryption attempted.')
            self.hints.append('Install TShark for deeper protocol dissection, USB HID analysis and protocol object extraction.')
            return
        import tempfile
        with tempfile.TemporaryDirectory(prefix='flagforge-tshark-') as tmp:
            root = Path(tmp)
            capture = root / 'capture.pcapng'
            capture.write_bytes(data)
            base = ['tshark', '-r', str(capture), '-n', '-Q']
            secret = None
            if self.tls_keylog:
                secret = root / 'capture.keys'
                secret.write_bytes(self.tls_keylog)
                base += ['-o', f'tls.keylog_file:{secret}']
            try:
                extracted = 0
                # Wireshark export-object handlers; unsupported types fail quietly.
                for protocol in ('http', 'smb', 'tftp', 'imf', 'ftp-data'):
                    if extracted >= 40 or len(self.artifacts) >= MAX_ARTIFACTS - 5: break
                    export_dir = root / ('export-' + protocol)
                    export_dir.mkdir()
                    try:
                        subprocess.run(base + ['--export-objects', f'{protocol},{export_dir}'],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=8, check=False)
                    except (OSError, subprocess.TimeoutExpired):
                        continue
                    for item in list(export_dir.iterdir())[:25]:
                        if extracted >= 40: break
                        if not item.is_file() or item.is_symlink() or item.stat().st_size > 1_500_000:
                            continue
                        raw = item.read_bytes()
                        self.add_artifact(item.name, raw, f'TShark {protocol.upper()} object')
                        self.inspect(item.name, raw, 1, f'TShark {protocol.upper()} object')
                        extracted += 1
                if extracted:
                    self.add_evidence(f'TShark exported {extracted} transferred object(s) from supported protocols.')
                if self.tls_keylog:
                    self.add_evidence('TShark attempted TLS decryption with an optional local key log; secrets are excluded from results.')
                # USB boot keyboard reports are encoded in packet fields.
                # Testing every field separately avoids invalid field aborts on older TShark.
                for field in ('usb.capdata', 'usbhid.data'):
                    try:
                        run = subprocess.run(base + ['-T','fields','-e',field],
                                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                             stderr=subprocess.DEVNULL, timeout=8, check=False)
                    except (OSError, subprocess.TimeoutExpired):
                        continue
                    if run.returncode != 0: continue
                    reports = []
                    for line in run.stdout[:400_000].splitlines():
                        hexdigits = re.sub(rb'[^0-9a-fA-F]', b'', line)
                        if len(hexdigits) == 16:
                            try: reports.append(bytes.fromhex(hexdigits.decode()))
                            except ValueError: pass
                    if not reports: continue
                    decoded = recover_hid_keystrokes(reports)
                    if decoded:
                        self.add_artifact('usb-keyboard-recovered.txt', decoded.encode(), 'TShark USB HID keyboard replay')
                        self.scan_bytes(decoded.encode(), 'USB HID keyboard replay')
                        self.add_evidence(f'Replayed {len(reports)} USB HID report(s) via {field} (US boot-keyboard layout assumption).')
                        break
            finally:
                if secret and secret.exists():
                    secret.write_bytes(b'')

    def inspect_zeek(self, data, cap):
        """Optional Zeek protocol logs. All log parsing is bounded and kept local."""
        if not shutil.which('zeek'):
            return
        import tempfile
        with tempfile.TemporaryDirectory(prefix='flagforge-zeek-') as tmp:
            root = Path(tmp)
            capture = root / 'capture.pcap'
            capture.write_bytes(data)
            try:
                result = subprocess.run(['zeek', '-r', str(capture), 'LogAscii::use_json=T'],
                                        cwd=root, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        timeout=18, check=False)
            except (OSError, subprocess.TimeoutExpired):
                self.hints.append('Zeek log generation timed out or was unavailable.')
                return
            if result.returncode != 0:
                self.hints.append('Zeek reported an analysis error; built-in PCAP results remain available.')
                return
            cap['zeek'] = []
            for name in ('dns', 'http', 'ssl', 'ftp', 'smtp', 'files', 'conn', 'weird'):
                path = root / (name + '.log')
                if not path.is_file() or path.stat().st_size > 1_000_000:
                    continue
                raw = path.read_bytes()[:350_000]
                lines = [line for line in raw.splitlines() if line.startswith(b'{')]
                cap['zeek'].append({'log': name, 'records': len(lines),
                                    'sample': [line[:200].decode('utf-8', 'replace') for line in lines[:2]]})
                self.add_artifact('zeek-' + name + '.jsonl', raw, 'Zeek offline protocol log')
                for line in lines[:150]:
                    self.scan_bytes(line, f'Zeek {name}.log', decode=False)
            if cap['zeek']:
                self.add_evidence('Generated ' + str(len(cap['zeek'])) + ' offline Zeek protocol logs for cross-checking.')

    def inspect_external(self, name, data, kind):
        import tempfile
        # Names are intentionally random; never interpolate filename into a command.
        with tempfile.TemporaryDirectory(prefix='flagforge-') as tmp:
            path = Path(tmp) / ('sample' + Path(name).suffix[:10])
            path.write_bytes(data)
            if shutil.which('exiftool'):
                details = invoke('exiftool', ['-json', str(path)], timeout=5, limit=5000)
                if details:
                    self.scan_bytes(details.encode(), f'{name} exiftool metadata')
                    self.add_evidence('ExifTool metadata: ' + details[:450])
            if shutil.which('tesseract') and kind in ('PNG image', 'JPEG image', 'BMP image', 'GIF image'):
                details = invoke('tesseract', [str(path), 'stdout'], timeout=10, limit=15_000)
                if details:
                    self.scan_bytes(details.encode(), f'{name} OCR text')
                    self.add_evidence('OCR produced searchable image text.')
            if shutil.which('zbarimg') and kind in ('PNG image', 'JPEG image', 'BMP image', 'GIF image'):
                details = invoke('zbarimg', ['--quiet', '--raw', str(path)], timeout=6, limit=8000)
                if details:
                    self.scan_bytes(details.encode(), f'{name} QR / barcode')
                    self.add_evidence('QR/barcode decoding produced searchable text.')
            if shutil.which('zsteg') and kind == 'PNG image':
                details = invoke('zsteg', ['-a', str(path)], timeout=10, limit=12_000)
                if details:
                    self.scan_bytes(details.encode(), f'{name} zsteg channels')
                    self.add_evidence('zsteg bit-plane analysis: ' + details[:400])
            if shutil.which('binwalk') and kind not in ('Text / source', 'PCAP / PCAPNG'):
                details = invoke('binwalk', [str(path)], timeout=7, limit=3500)
                if details:
                    self.add_evidence('Binwalk signatures: ' + details[:450])
            if shutil.which('ffprobe') and kind in ('WAV audio', 'MP3 audio'):
                details = invoke('ffprobe', ['-v', 'quiet', '-show_format', '-show_streams', str(path)], timeout=5, limit=3500)
                if details:
                    self.scan_bytes(details.encode(), f'{name} audio metadata')
                    self.add_evidence('ffprobe metadata available.')

    def finish(self):
        rank_flags(self.flags, self.question)
        plan = investigation_plan(self.question, self.pcap, self.flags, self.artifact_info)
        return {'flags': self.flags[:100], 'decodes': self.decodes[:80],
                'artifacts': self.artifact_info, 'files': self.files[:100], 'evidence': self.evidence,
                'hints': list(dict.fromkeys(self.hints))[:30], 'metadata': self.metadata,
                'pcap': self.pcap, 'investigation': plan,
                'stats': {'flags': len(self.flags), 'files': len(self.files),
                          'artifacts': len(self.artifact_info), 'decodings': len(self.decodes),
                          'packets': self.pcap['packets'] if self.pcap else 0},
                'disclaimer': 'Candidate flags are extracted evidence, not guaranteed accepted answers.'}

