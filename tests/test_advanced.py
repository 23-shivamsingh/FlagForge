"""Regression coverage for question routing and advanced passive PCAP passes."""
import zipfile
import base64
import gzip
import io
import struct

from fastapi.testclient import TestClient
from app.main import app
from app.advanced_pcap import challenge_intents, dns_reconstructions, recover_hid_keystrokes, tls_sni
from app.pcap import parse_http

client = TestClient(app)


def _dns_query(label):
    labels = label.split('.')
    qname = b''.join(bytes([len(part)]) + part.encode() for part in labels) + b'\x00'
    return struct.pack('!HHHHHH', 1, 0x0100, 1, 0, 0, 0) + qname + struct.pack('!HH', 1, 1)


def _udp_packet(payload):
    udp = struct.pack('!HHHH', 65000, 53, len(payload)+8, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(udp)+20, 1, 0, 64, 17, 0, b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02')
    return b'\x00'*12+b'\x08\x00'+ip+udp


def _pcap(frames):
    raw = bytearray(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 1))
    for i, frame in enumerate(frames):
        raw += struct.pack('<IIII', i, 0, len(frame), len(frame)) + frame
    return bytes(raw)


def test_dns_exfiltration_segment_reassembly():
    encoded = base64.b64encode(b'spooky{dns_fragments_recovered}').decode()
    parts = [encoded[:14], encoded[14:28], encoded[28:]]
    capture = _pcap([_udp_packet(_dns_query(f'{idx:04}.{part}.exfil.test')) for idx,part in enumerate(parts)])
    r = client.post('/api/analyze', data={'question': 'Find hidden data in DNS queries. Flag format spooky{...}'},
                    files={'file': ('dns.pcap', capture)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert 'dns' in body['investigation']['intents']
    assert any(x['value'] == 'spooky{dns_fragments_recovered}' for x in body['flags'])
    assert any('sequence index' in x['source'] for x in body['pcap']['dns_reassembled'])
    assert body['flags'][0]['score'] >= 60


def test_http_chunked_gzip_recovery():
    answer = b'flag{http_gzip_and_chunks}'
    blob = gzip.compress(answer)
    chunked = b'%x\r\n' % len(blob) + blob + b'\r\n0\r\n\r\n'
    stream = (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n'
              b'Content-Encoding: gzip\r\nContent-Type: text/plain\r\n\r\n'+chunked)
    records, artifacts = parse_http(stream, 'host:80', 'client:4000')
    assert records[0]['content_type'] == 'text/plain'
    assert records[0]['body_size'] == len(blob)
    assert any(answer == value for _, value in artifacts)


def test_hid_keystrokes_reconstruction():
    def rep(mod, key): return bytes([mod,0,key,0,0,0,0,0])
    # f,l,a,g,SHIFT+[ , x, SHIFT+] -> flag{...}
    sequence = [(0,9),(0,15),(0,4),(0,10),(2,47),(0,27),(2,48)]
    frames = []
    for mod,key in sequence:
        frames.extend([rep(mod,key),rep(0,0)])
    assert recover_hid_keystrokes(frames) == 'flag{x}'


def test_question_format_and_ranking():
    r=client.post('/api/analyze',data={'question':'My team hid a secret in HTTP headers. Format: guild{...}',
                                      'text':'guild{question_routed_works}'})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body['flags'][0]['value'] == 'guild{question_routed_works}'
    assert body['flags'][0]['verified'] is False
    assert body['flags'][0]['reasons']
    assert body['investigation']['intents'][0] == 'http'
    assert body['investigation']['steps']


def test_standalone_decoder():
    token=base64.b64encode(b'flag{standalone_decode_lab}').decode()
    r=client.post('/api/decode',json={'text':token})
    assert r.status_code == 200,r.text
    assert 'flag{standalone_decode_lab}' in r.json()['flags']
    assert r.json()['chains']
    assert client.post('/api/decode',json={'text':'abc','prefix':'(x)+'}).status_code==422


def test_sample_and_limits():
    r=client.get('/api/sample/pcap')
    assert r.status_code == 200 and r.content.startswith(b'\xd4\xc3\xb2\xa1')
    assert client.get('/api/sample/../../app/main.py').status_code in (404, 400)
    too_long = client.post('/api/analyze',data={'text':'hello', 'question':'q'*3001})
    assert too_long.status_code == 422


def test_domain_concatenation_no_false_group():
    assert dns_reconstructions([{'kind':'query','name':'one.example.test'}]) == []
    assert challenge_intents('Find the secret in USB keystrokes')[0]=='keyboard'


def test_utf16_flag_hidden_in_binary():
    payload = b'\x99\xaa\x01\x02' + 'spooky{utf16_message}'.encode('utf-16le') + b'\x00\x00'
    r = client.post('/api/analyze',files={'file':('payload.bin',payload)})
    assert r.status_code == 200,r.text
    assert any(f['value']=='spooky{utf16_message}' for f in r.json()['flags'])


def test_icmp_payload_reassembly():
    message = b'flag{icmp_split_payload}'
    frames = []
    for offset in range(0, len(message), 5):
        datagram = struct.pack('!BBHHH',8,0,0,0x999,offset//5) + message[offset:offset+5]
        ip=struct.pack('!BBHHHBBH4s4s',0x45,0,len(datagram)+20,offset//5,0,64,1,0,
                       b'\x0a\x00\x00\x01',b'\x0a\x00\x00\x02')
        frames.append(b'\x00'*12+b'\x08\x00'+ip+datagram)
    r=client.post('/api/analyze',files={'file':('ping.pcap',_pcap(frames))},data={'question':'Find the covert ICMP message'})
    assert r.status_code==200,r.text
    assert any(f['value']=='flag{icmp_split_payload}' for f in r.json()['flags'])
    assert r.json()['pcap']['covert']


def test_zip_carving_inside_non_http_stream():
    import zipfile
    zipped=io.BytesIO()
    with zipfile.ZipFile(zipped,'w') as z:
        z.writestr('flag.txt','flag{embedded_zip_inside_tcp}')
    blob=zipped.getvalue()
    # Use the built-in Inspector direct stream carve to avoid relying on TShark.
    from app.core import Inspector
    i=Inspector()
    i.inspect_stream_carving('tcp-stream-01.bin',b'HELLO PREFIX\x00'+blob)
    assert any(f['value']=='flag{embedded_zip_inside_tcp}' for f in i.finish()['flags'])


def test_pcap_trailer_base64_metadata():
    # A PCAP comment-like trailer is not a packet; it should still be inspected.
    encoded=base64.b64encode(b'flag{capture_metadata_encoded}').decode()
    capture=_pcap([])+b'CTFnote=' + encoded.encode() + b';'
    r=client.post('/api/analyze',files={'file':('metadata.pcap',capture)})
    assert r.status_code==200,r.text
    assert any(f['value']=='flag{capture_metadata_encoded}' for f in r.json()['flags'])


def test_case_bundle_contains_report_and_recovered_artifacts():
    result=client.post('/api/analyze',data={'text':'flag{bundle_success}'})
    assert result.status_code==200
    response=client.get('/api/bundle/'+result.json()['job_id'])
    assert response.status_code==200
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert 'flagforge-report.json' in archive.namelist()
        assert 'MANIFEST.txt' in archive.namelist()
        assert b'flag{bundle_success}' in archive.read('flagforge-report.json')


def test_no_false_usb_intent_from_hidden():
    from app.advanced_pcap import challenge_intents
    intents=challenge_intents('Find the hidden flag in the TCP stream.')
    assert 'streams' in intents
    assert 'keyboard' not in intents
