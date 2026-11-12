"""Passive PCAP/PCAPNG triage with bounded stream reconstruction. No packet capture."""
import collections
import ipaddress
import re
import struct
from typing import Iterator

MAX_PACKETS = 30_000
MAX_STREAM = 750_000
MAX_EXTRACT = 1_500_000


def iter_capture(blob: bytes) -> Iterator[tuple[int, bytes]]:
    if len(blob) < 16:
        raise ValueError('Capture header is incomplete.')
    magic = blob[:4]
    orders = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
              b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
    if magic in orders:
        order = orders[magic]
        if len(blob) < 24:
            raise ValueError('Truncated classic PCAP header.')
        linktype = struct.unpack_from(order + 'I', blob, 20)[0] & 0xffff
        pos = 24
        for _ in range(MAX_PACKETS):
            if pos + 16 > len(blob):
                break
            _sec, _usec, size, _original = struct.unpack_from(order + 'IIII', blob, pos)
            pos += 16
            if size > 2_000_000 or pos + size > len(blob):
                break
            yield linktype, blob[pos:pos + size]
            pos += size
        return
    if magic != b'\x0a\x0d\x0d\x0a':
        raise ValueError('Not a recognized PCAP or PCAPNG file.')
    pos = 0
    interfaces = []
    order = '<'
    count = 0
    while pos + 12 <= len(blob) and count < MAX_PACKETS:
        if blob[pos:pos + 4] == b'\x0a\x0d\x0d\x0a':
            bom = blob[pos + 8:pos + 12]
            order = '<' if bom == b'\x4d\x3c\x2b\x1a' else '>' if bom == b'\x1a\x2b\x3c\x4d' else ''
            if not order:
                raise ValueError('Unknown PCAPNG byte order.')
            interfaces = []
        kind, length = struct.unpack_from(order + 'II', blob, pos)
        if length < 12 or length % 4 or pos + length > len(blob):
            break
        if kind == 1 and length >= 20:
            interfaces.append(struct.unpack_from(order + 'H', blob, pos + 8)[0])
        elif kind == 6 and length >= 32:
            if_id, _high, _low, cap_len, _original = struct.unpack_from(order + 'IIIII', blob, pos + 8)
            if cap_len <= 2_000_000 and pos + 28 + cap_len <= pos + length - 4:
                linktype = interfaces[if_id] if if_id < len(interfaces) else 1
                yield linktype, blob[pos + 28:pos + 28 + cap_len]
                count += 1
        elif kind == 3 and length >= 16:  # Simple Packet Block
            original = struct.unpack_from(order + 'I', blob, pos + 8)[0]
            payload = blob[pos + 12:pos + length - 4]
            linktype = interfaces[0] if interfaces else 1
            yield linktype, payload[:min(original, len(payload))]
            count += 1
        pos += length


def dns_names(payload: bytes):
    """DNS QNAME and TXT extraction with pointer loop protection."""
    result = []
    if len(payload) < 12:
        return result
    counts = struct.unpack_from('!HHHH', payload, 4)
    pos = 12

    def name_at(offset):
        labels = []
        jumps = 0
        resume = None
        while offset < len(payload) and jumps < 30:
            size = payload[offset]
            if size & 0xc0 == 0xc0:
                if offset + 1 >= len(payload): break
                ptr = ((size & 0x3f) << 8) | payload[offset + 1]
                if resume is None: resume = offset + 2
                offset = ptr
                jumps += 1
                continue
            offset += 1
            if size == 0:
                return '.'.join(labels), (resume if resume is not None else offset)
            if size > 63 or offset + size > len(payload):
                break
            labels.append(payload[offset:offset + size].decode('ascii', 'replace'))
            offset += size
            jumps += 1
        return '.'.join(labels), (resume if resume is not None else offset)

    for _ in range(min(counts[0], 50)):
        n, pos = name_at(pos)
        if pos + 4 > len(payload): return result
        typ = struct.unpack_from('!H', payload, pos)[0]
        pos += 4
        if n: result.append({'kind': 'query', 'name': n[:250], 'type': typ})
    for _ in range(min(counts[1], 50)):
        n, pos = name_at(pos)
        if pos + 10 > len(payload): break
        typ, _cls, _ttl, size = struct.unpack_from('!HHIH', payload, pos)
        pos += 10
        if pos + size > len(payload): break
        if typ == 16 and size:
            rdata = payload[pos:pos + size]
            txt = []
            i = 0
            while i < len(rdata):
                width = rdata[i]
                i += 1
                txt.append(rdata[i:i + width].decode('latin-1', 'replace'))
                i += width
            result.append({'kind': 'TXT', 'name': n[:250], 'value': ''.join(txt)[:500]})
        pos += size
    return result


def parse_ip(linktype, frame):
    if linktype == 1 and len(frame) >= 14:  # Ethernet
        ether = int.from_bytes(frame[12:14], 'big')
        pos = 14
        for _ in range(2):
            if ether in (0x8100, 0x88a8) and len(frame) >= pos + 4:
                ether = int.from_bytes(frame[pos + 2:pos + 4], 'big')
                pos += 4
        if ether not in (0x0800, 0x86dd):
            return None
        frame = frame[pos:]
    elif linktype == 113 and len(frame) >= 16:  # Linux cooked v1
        proto = int.from_bytes(frame[14:16], 'big')
        if proto not in (0x0800, 0x86dd): return None
        frame = frame[16:]
    elif linktype == 101:  # Raw IP
        pass
    else:
        return None
    if not frame:
        return None
    version = frame[0] >> 4
    if version == 4 and len(frame) >= 20:
        ihl = (frame[0] & 15) * 4
        if ihl < 20 or len(frame) < ihl: return None
        if int.from_bytes(frame[6:8], 'big') & 0x1fff: return None  # fragment
        size = int.from_bytes(frame[2:4], 'big')
        packet = frame[ihl:size or len(frame)]
        src, dst = str(ipaddress.IPv4Address(frame[12:16])), str(ipaddress.IPv4Address(frame[16:20]))
        protocol = frame[9]
        ipid = int.from_bytes(frame[4:6], 'big')
        hop = frame[8]
    elif version == 6 and len(frame) >= 40:
        size = int.from_bytes(frame[4:6], 'big')
        protocol = frame[6]
        ipid = None
        hop = frame[7]
        src = str(ipaddress.IPv6Address(frame[8:24]))
        dst = str(ipaddress.IPv6Address(frame[24:40]))
        packet = frame[40:40 + size]
        # Ignore extension header chains; tshark can decode these if installed.
    else:
        return None
    if protocol == 6 and len(packet) >= 20:
        source_port, dest_port, seq = struct.unpack_from('!HHI', packet, 0)
        offset = (packet[12] >> 4) * 4
        if offset < 20 or len(packet) < offset: return None
        return {'proto': 'TCP', 'src': src, 'dst': dst, 'sport': source_port,
                'dport': dest_port, 'seq': seq, 'payload': packet[offset:], 'ip_id': ipid, 'hop': hop}
    if protocol == 17 and len(packet) >= 8:
        source_port, dest_port = struct.unpack_from('!HH', packet, 0)
        return {'proto': 'UDP', 'src': src, 'dst': dst, 'sport': source_port,
                'dport': dest_port, 'seq': None, 'payload': packet[8:], 'ip_id': ipid, 'hop': hop}
    return {'proto': {1: 'ICMP', 58: 'ICMPv6'}.get(protocol, f'IP/{protocol}'),
            'src': src, 'dst': dst, 'sport': 0, 'dport': 0, 'seq': None, 'payload': packet[:1000], 'ip_id': ipid, 'hop': hop}


def _unchunk(body: bytes) -> bytes:
    """Bounded HTTP chunked transfer decoding; rejects broken framing."""
    pos = 0
    out = bytearray()
    for _ in range(3000):
        newline = body.find(b'\r\n', pos, min(pos + 150, len(body)))
        if newline < 0:
            return b''
        try:
            size = int(body[pos:newline].split(b';')[0].strip(), 16)
        except ValueError:
            return b''
        pos = newline + 2
        if size == 0:
            return bytes(out)
        if size > MAX_EXTRACT - len(out) or pos + size + 2 > len(body):
            return b''
        out.extend(body[pos:pos+size])
        pos += size
        if body[pos:pos+2] != b'\r\n':
            return b''
        pos += 2
    return b''


def parse_http(stream, src, dst):
    outputs = []
    artifacts = []
    pattern = rb'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^\r\n]{1,200} HTTP/1\.[01]\r\n|HTTP/1\.[01] \d{3} [^\r\n]{0,100}\r\n'
    matches = list(re.finditer(pattern, stream))[:35]
    for i, match in enumerate(matches):
        offset = match.start()
        head_end = stream.find(b'\r\n\r\n', offset, offset + 16_384)
        if head_end == -1: continue
        header = stream[offset:head_end].decode('latin-1', 'replace')
        lines = header.split('\r\n')
        lower = header.lower()
        start_body = head_end + 4
        next_offset = matches[i + 1].start() if i + 1 < len(matches) else len(stream)
        next_offset = max(start_body, next_offset)
        content_len = re.search(r'(?im)^content-length:\s*(\d+)', header)
        body = b''
        if 'transfer-encoding: chunked' in lower:
            body = _unchunk(stream[start_body: min(start_body + MAX_EXTRACT * 2, next_offset)])
        elif content_len:
            count = min(int(content_len.group(1)), MAX_EXTRACT)
            body = stream[start_body:start_body + count]
        elif start_body < next_offset and next_offset - start_body <= MAX_EXTRACT:
            body = stream[start_body:next_offset].rstrip(b'\r\n')
        content_type = re.search(r'(?im)^content-type:\s*([^\r\n]+)', header)
        path = lines[0][:220]
        outputs.append({'line': path, 'source': src, 'destination': dst,
                        'headers': lines[1:20], 'body_size': len(body),
                        'content_type': content_type.group(1)[:100] if content_type else ''})
        if body:
            artifacts.append((f'http-body-{len(outputs)}.bin', body))
            compression = 'gzip' if 'content-encoding: gzip' in lower else 'deflate' if 'content-encoding: deflate' in lower else None
            if compression:
                import zlib
                for wbits in ([16 + zlib.MAX_WBITS] if compression == 'gzip' else [zlib.MAX_WBITS, -zlib.MAX_WBITS]):
                    try:
                        d = zlib.decompressobj(wbits)
                        uncompressed = d.decompress(body, MAX_EXTRACT + 1)
                        if d.eof and len(uncompressed) <= MAX_EXTRACT:
                            artifacts.append((f'http-body-{len(outputs)}-decompressed.bin', uncompressed))
                            break
                    except zlib.error:
                        pass
    return outputs, artifacts


def parse_capture(blob: bytes):
    counters = collections.Counter()
    conversations = collections.Counter()
    streams = collections.defaultdict(list)
    udp_samples = []
    payload_samples = []
    dns = []
    endpoints = collections.Counter()
    packets = 0
    packet_rows = []
    icmp_series = collections.defaultdict(list)
    ipid_series = collections.defaultdict(list)
    for linktype, raw in iter_capture(blob):
        packets += 1
        record = parse_ip(linktype, raw)
        if not record:
            counters['Other / unsupported'] += 1
            continue
        proto, src, dst = record['proto'], record['src'], record['dst']
        if len(packet_rows) < 250:
            packet_rows.append({'number': packets, 'src': src, 'dst': dst, 'protocol': proto,
                                'sport': record['sport'], 'dport': record['dport'],
                                'size': len(raw), 'payload_hex': record['payload'][:80].hex(' ')})
        payload = record['payload']
        if proto in ('ICMP', 'ICMPv6') and len(payload) >= 8:
            # The ICMP payload begins after type/checksum/id/sequence on echo frames.
            icmp_type = payload[0]
            if icmp_type in (0, 8, 128, 129) and len(icmp_series[(src, dst, icmp_type)]) < 500:
                icmp_series[(src, dst, icmp_type)].append(payload[8:][:400])
        if record.get('ip_id') is not None and len(ipid_series[(src, dst)]) < 500:
            ipid_series[(src, dst)].append(record['ip_id'])
        label = 'DNS' if proto == 'UDP' and (record['sport'] == 53 or record['dport'] == 53) else proto
        counters[label] += 1
        endpoints[src] += 1
        endpoints[dst] += 1
        conn = f'{src}:{record["sport"]} → {dst}:{record["dport"]} ({proto})'
        conversations[conn] += 1
        if not payload:
            continue
        if proto not in ('TCP', 'UDP') and len(payload_samples) < 50:
            payload_samples.append({'path': conn, 'preview': payload[:1500].decode('latin-1', 'replace'), 'hex': payload[:100].hex()})
        if proto == 'TCP':
            key = (src, record['sport'], dst, record['dport'])
            if len(streams[key]) < 8_000:
                streams[key].append((record['seq'], payload))
        elif proto == 'UDP':
            if len(udp_samples) < 25:
                udp_samples.append({'path': conn, 'preview': payload[:500].decode('latin-1', 'replace'), 'hex': payload[:100].hex()})
            if label == 'DNS' and len(dns) < 200:
                dns.extend(dns_names(payload))
    stream_view = []
    stream_raw = []
    http = []
    extracted = []
    for (src, sport, dst, dport), segments in sorted(streams.items(), key=lambda x: -len(x[1]))[:50]:
        # Naive TCP sequence reassembly: removes overlapping/retransmitted bytes,
        # preserves gaps as separate contiguous fragments instead of inventing bytes.
        data = bytearray()
        end = None
        gap_count = 0
        for seq, payload in sorted(segments, key=lambda x: x[0]):
            if end is None:
                data.extend(payload[:MAX_STREAM]); end = seq + len(payload)
            elif seq > end:
                gap_count += 1
                data.extend(b'\n[PCAP GAP]\n')
                data.extend(payload[:max(0, MAX_STREAM - len(data))]); end = seq + len(payload)
            elif seq + len(payload) > end:
                tail = payload[end - seq:]
                data.extend(tail[:max(0, MAX_STREAM - len(data))]); end = seq + len(payload)
            if len(data) >= MAX_STREAM: break
        reassembled = bytes(data)
        ident = f'{src}:{sport} → {dst}:{dport}'
        stream_view.append({'id': len(stream_view), 'path': ident, 'size': len(reassembled),
                            'fragments': len(segments), 'gaps': gap_count,
                            'preview': reassembled[:900].decode('latin-1', 'replace'),
                            'hex': reassembled[:120].hex(' ')})
        stream_raw.append((f'tcp-stream-{len(stream_view):02d}.bin', reassembled))
        h, a = parse_http(reassembled, f'{src}:{sport}', f'{dst}:{dport}')
        http.extend(h); extracted.extend(a)
    return {
        'packets': packets,
        'protocols': [{'name': k, 'count': v} for k, v in counters.most_common(12)],
        'conversations': [{'path': k, 'packets': v} for k, v in conversations.most_common(25)],
        'endpoints': [{'ip': k, 'packets': v} for k, v in endpoints.most_common(20)],
        'dns': dns[:200], 'http': http[:50], 'packet_rows': packet_rows,
        'streams': stream_view[:50], 'udp_samples': udp_samples, 'payload_samples': payload_samples,
        '_stream_blobs': stream_raw,
        '_extracted': extracted[:25],
        '_icmp_series': [(f'{src} → {dst} / ICMP type {typ}', chunks) for (src, dst, typ), chunks in icmp_series.items()],
        '_ipid_series': [(f'{src} → {dst}', ids) for (src, dst), ids in ipid_series.items()],
    }
