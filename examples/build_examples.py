"""Generate small, wholly synthetic test fixtures for the FlagForge UI."""
import base64
import io
import struct
import zipfile
from pathlib import Path
from PIL import Image

FOLDER=Path(__file__).resolve().parent
FOLDER.mkdir(exist_ok=True)
message=b'spooky{synthetic_network_flag}'
encoded=base64.b64encode(message)
http=b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: '+str(len(encoded)).encode()+b'\r\n\r\n'+encoded
frames=[]
for seq,payload in [(100,http[:45]),(145,http[45:])]:
    tcp=struct.pack('!HHIIHHHH',12345,80,seq,0,0x5018,4096,0,0)+payload
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,len(tcp)+20,1,0,64,6,0,b'\x0a\x00\x00\x01',b'\x0a\x00\x00\x02')
    frames.append(b'\x00'*12+b'\x08\x00'+ip+tcp)
cap=bytearray(b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,65535,1))
for i,frame in enumerate(frames):
    cap+=struct.pack('<IIII',i+1,0,len(frame),len(frame))+frame
(FOLDER/'demo-capture.pcap').write_bytes(cap)
(FOLDER/'demo-encoding.txt').write_text('Base64 evidence: '+base64.b64encode(b'flag{synthetic_encoded_text}').decode()+'\n')
with zipfile.ZipFile(FOLDER/'demo-archive.zip','w') as z:
    z.writestr('hidden/secret.txt','flag{synthetic_archive_flag}\n')
img=Image.new('RGB',(40,40),(0,0,0));pixels=[(0,0,0)]*(40*40)
bitstream = [(v >> (7-i))&1 for v in b'flag{synthetic_pixel_flag}' for i in range(8)]
for i,v in enumerate(bitstream): pixels[i]=(v,0,0)
img.putdata(pixels);img.save(FOLDER/'demo-image.png')
print('Created synthetic demo challenges in examples/')
