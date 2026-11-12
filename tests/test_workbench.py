import base64
import io
import struct
import zipfile
from fastapi.testclient import TestClient
from PIL import Image

from app.core import Inspector
from app.main import app
from app.pcap import parse_capture

client = TestClient(app)


def tcp_packet(seq, payload, src=b'\x0a\x00\x00\x01', dst=b'\x0a\x00\x00\x02'):
    tcp = struct.pack('!HHIIHHHH', 4343, 80, seq, 0, 0x5018, 8192, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(tcp) + 20, 42, 0, 64, 6, 0, src, dst)
    ethernet = b'\x00'*12 + b'\x08\x00'
    return ethernet + ip + tcp


def pcap_from_frames(frames):
    output = bytearray(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 1))
    for i, frame in enumerate(frames):
        output.extend(struct.pack('<IIII', i + 1, 0, len(frame), len(frame)))
        output.extend(frame)
    return bytes(output)


def pcapng_from_frames(frames):
    def block(typ, body):
        pad = (-len(body)) % 4
        body += b'\x00'*pad
        size = len(body) + 12
        return struct.pack('<II',typ,size) + body + struct.pack('<I',size)
    content = bytearray(block(0x0a0d0d0a, struct.pack('<IHHq',0x1a2b3c4d,1,0,-1)))
    content.extend(block(1,struct.pack('<HHI',1,0,65535)))
    for frame in frames:
        content.extend(block(6,struct.pack('<IIIII',0,0,0,len(frame),len(frame)) + frame))
    return bytes(content)


def test_text_direct_flag():
    answer=client.post('/api/analyze',data={'text':'Hello spooky{found_in_text} world'})
    assert answer.status_code == 200
    assert any(x['value']=='spooky{found_in_text}' for x in answer.json()['flags'])


def test_custom_prefix():
    answer=client.post('/api/analyze',data={'text':'hackme{custom_match}' ,'prefix':'hackme'})
    assert any(x['value']=='hackme{custom_match}' for x in answer.json()['flags'])
    invalid=client.post('/api/analyze',data={'text':'a', 'prefix':'(a+)+$'})
    assert invalid.status_code == 422


def test_base64_flag_hunt():
    text='Encoded: '+base64.b64encode(b'flag{decoded_base64}').decode()
    answer=client.post('/api/analyze',data={'text':text})
    assert any(x['value']=='flag{decoded_base64}' for x in answer.json()['flags'])


def test_fragmented_http_pcap():
    content=base64.b64encode(b'spooky{tcp_reassembly_wins}')
    response=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(content)).encode()+b'\r\n\r\n'+content
    frames=[tcp_packet(1000,response[:37]),tcp_packet(1037,response[37:])]
    answer=client.post('/api/analyze',files={'file':('challenge.pcap',pcap_from_frames(frames),'application/octet-stream')})
    assert answer.status_code == 200,answer.text
    data=answer.json()
    assert data['pcap']['packets']==2
    assert data['pcap']['streams'][0]['fragments']==2
    assert data['pcap']['http'][0]['body_size']==len(content)
    assert any(x['value']=='spooky{tcp_reassembly_wins}' for x in data['flags'])
    stream_id = data['pcap']['streams'][0]['artifact_id']
    download=client.get(f"/api/artifact/{data['job_id']}/{stream_id}")
    assert download.status_code == 200
    assert download.content==response


def test_pcapng_support():
    raw=pcapng_from_frames([tcp_packet(10,b'flag{pcapng_works}')])
    result=parse_capture(raw)
    assert result['packets']==1
    assert b'flag{pcapng_works}' in result['_stream_blobs'][0][1]


def test_zip_extract_traversal_not_written(tmp_path):
    packed=io.BytesIO()
    with zipfile.ZipFile(packed,'w') as z:
        z.writestr('../../secret.txt','flag{zip_entry_found}')
    result=client.post('/api/analyze',files={'file':('archive.zip',packed.getvalue(),'application/zip')})
    assert result.status_code==200,result.text
    data=result.json()
    assert any(x['value']=='flag{zip_entry_found}' for x in data['flags'])
    assert not (tmp_path / 'secret.txt').exists()
    assert any(x['name']=='secret.txt' for x in data['files'])


def test_png_lsb_single_channel():
    message=b'flag{pixel_bit_plane}'
    img=Image.new('RGB',(40,40),(0,0,0))
    pixels=[(0,0,0)]*(40*40)
    bits = [(c >> (7-i)) & 1 for c in message for i in range(8)]
    for i,bit in enumerate(bits):
        pixels[i]=(bit,0,0)
    img.putdata(pixels)
    buf=io.BytesIO();img.save(buf,format='PNG')
    result=client.post('/api/analyze',files={'file':('stego.png',buf.getvalue(),'image/png')})
    assert result.status_code==200,result.text
    assert any(x['value']=='flag{pixel_bit_plane}' for x in result.json()['flags'])


def test_report_and_headers():
    r=client.post('/api/analyze',data={'text':'flag{test_export}'})
    report=client.get('/api/report/'+r.json()['job_id'])
    assert report.status_code==200
    assert report.json()['stats']['flags']>=1
    assert report.headers['content-disposition'].startswith('attachment;')
    assert client.get('/api/artifact/not-existing/a001').status_code==404
    assert client.get('/api/health').json()['status']=='ok'


def test_reject_cross_origin_and_oversize():
    r=client.post('/api/analyze',data={'text':'a'},headers={'origin':'https://not-flagforge.example'})
    assert r.status_code==403
    r=client.post('/api/analyze',files={'file':('huge.bin',b'1'*(35*1024*1024+1))})
    assert r.status_code==413


def udp_packet(payload, sport=5353, dport=53):
    udp = struct.pack('!HHHH',sport,dport,len(payload)+8,0) + payload
    ip = struct.pack('!BBHHHBBH4s4s',0x45,0,len(udp)+20,1,0,64,17,0,
                     b'\x0a\x01\x00\x01',b'\x0a\x01\x00\x02')
    return b'\x00'*12+b'\x08\x00'+ip+udp


def test_dns_txt_flag():
    question = b'\x03ctf\x04test\x00' + struct.pack('!HH',16,1)
    content = b'flag{dns_txt_message}'
    answer = b'\xc0\x0c' + struct.pack('!HHIH',16,1,60,len(content)+1) + bytes([len(content)])+content
    dns = struct.pack('!HHHHHH',9,0x8180,1,1,0,0) + question + answer
    result=client.post('/api/analyze',files={'file':('dns.pcap',pcap_from_frames([udp_packet(dns)]),'application/octet-stream')})
    assert result.status_code == 200
    data=result.json()
    assert any(x['value']=='flag{dns_txt_message}' for x in data['flags'])
    assert any(x['kind']=='TXT' for x in data['pcap']['dns'])


def test_png_appended_zip_polyglot():
    im = Image.new('RGB',(8,8))
    buff=io.BytesIO(); im.save(buff,format='PNG')
    zbuf=io.BytesIO()
    with zipfile.ZipFile(zbuf,'w') as archive:
        archive.writestr('payload.txt','flag{appended_zip_carving}')
    result=client.post('/api/analyze',files={'file':('polyglot.png',buff.getvalue()+zbuf.getvalue(),'image/png')})
    assert result.status_code == 200, result.text
    data=result.json()
    assert any(x['value']=='flag{appended_zip_carving}' for x in data['flags'])
    assert any('appended' in x['name'] or 'image trailer' in x['source'] for x in data['artifacts'])


def test_optional_tls_key_log_validation():
    capture=pcap_from_frames([tcp_packet(20,b'test')])
    invalid=client.post('/api/analyze',files={'file':('net.pcap',capture),
                                                'tls_keylog':('secret.log',b'not a key log')})
    assert invalid.status_code == 422
    secret=b'CLIENT_RANDOM ' + b'a'*64 + b' ' + b'b'*96 + b'\n'
    valid=client.post('/api/analyze',files={'file':('net.pcap',capture),
                                              'tls_keylog':('secret.log',secret)})
    assert valid.status_code == 200
    body=valid.json()
    assert 'bbbb' not in str(body)


def test_markdown_writeup():
    result=client.post('/api/analyze',data={'text':'flag{markdown_writeup}'})
    writeup=client.get('/api/writeup/'+result.json()['job_id'])
    assert writeup.status_code==200
    assert '# FlagForge' in writeup.text
    assert 'flag{markdown_writeup}' in writeup.text
    assert 'not scoreboard-verified' in writeup.text
