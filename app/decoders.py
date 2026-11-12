"""Bounded, explainable decoders for captured CTF evidence."""
import base64
import binascii
import codecs
import gzip
import html
import re
import urllib.parse
import zlib
from collections import deque

MAX_TEXT = 60_000
MAX_STATES = 160
BASE64_TOKEN = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/])')
HEX_TOKEN = re.compile(r'(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){6,}(?![0-9a-fA-F])')
MORSE = dict(zip('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    '.- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. --.- .-. ... - ..- ...- .-- -..- -.-- --.. ----- .---- ..--- ...-- ....- ..... -.... --... ---.. ----.'.split()))


def legibility(data: bytes) -> float:
    if not data:
        return 0
    return sum(c in (9, 10, 13) or 32 <= c < 127 for c in data) / len(data)


def sample_text(blob: bytes, limit: int = 2000) -> str:
    return blob[:limit].decode('utf-8', 'replace')


def flag_regex(prefix=''):
    """Known CTF flag forms, or safely constrained user-supplied prefix."""
    if prefix:
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,29}', prefix):
            raise ValueError('Flag prefix must be 1–30 alphanumeric, - or _ characters.')
        head = re.escape(prefix)
    else:
        head = r'(?:flag|ctf|picoCTF|HTB|THM|spooky|DUCTF|CSAW|uiuctf|corCTF|ictf|buckeye|actf|nite|CYBER|SUCTF|volga)'
    return re.compile(r'(?<![A-Za-z0-9_])' + head + r'\{[^\x00-\x1f\x7f{}]{1,200}\}', re.I)


def extract_flags(blob: bytes | str, pattern) -> list[str]:
    text = blob if isinstance(blob, str) else blob.decode('latin-1', 'replace')
    return list(dict.fromkeys(x.group() for x in pattern.finditer(text[:MAX_TEXT])))[:40]


def decoded_options(text: str) -> list[tuple[str, bytes]]:
    """No eval, arbitrary decompression or network actions. Output lengths capped by caller."""
    t = text.strip()
    if not t:
        return []
    out = []
    compact = re.sub(r'\s+', '', t)
    if len(compact) >= 8 and re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', compact):
        try:
            padded = compact + '=' * (-len(compact) % 4)
            out.append(('base64', base64.b64decode(padded, validate=True)))
        except (ValueError, binascii.Error):
            pass
    if len(compact) >= 8 and len(compact) % 2 == 0 and re.fullmatch(r'[0-9a-fA-F]+', compact):
        try:
            out.append(('hex', bytes.fromhex(compact)))
        except ValueError:
            pass
    if len(compact) >= 16 and len(compact) % 8 == 0 and re.fullmatch('[01]+', compact):
        try:
            out.append(('binary-ascii', bytes(int(compact[i:i + 8], 2) for i in range(0, len(compact), 8))))
        except ValueError:
            pass
    if re.fullmatch(r'(?:\d{1,3}[ ,;\n]+){3,}\d{1,3}', t):
        try:
            nums = [int(x) for x in re.findall(r'\d+', t)]
            if all(0 <= n <= 255 for n in nums):
                out.append(('decimal-ascii', bytes(nums)))
        except ValueError:
            pass
    if '%' in t or '+' in t:
        try:
            unquoted = urllib.parse.unquote_to_bytes(t)
            if unquoted != t.encode('utf-8', 'replace'):
                out.append(('url-percent', unquoted))
        except ValueError:
            pass
    if '&' in t:
        unescaped = html.unescape(t)
        if unescaped != t:
            out.append(('html-entities', unescaped.encode()))
    if '\\x' in t or '\\u' in t:
        try:
            converted = codecs.decode(t, 'unicode_escape')
            if converted != t:
                out.append(('unicode-escape', converted.encode('utf-8', 'replace')))
        except (ValueError, UnicodeError):
            pass
    if re.fullmatch(r'[A-Z2-7]+=*', compact, re.I) and len(compact) >= 16:
        try:
            out.append(('base32', base64.b32decode(compact.upper() + '=' * (-len(compact) % 8))))
        except (ValueError, binascii.Error):
            pass
    if re.fullmatch(r'[.\- /]{5,}', t) and ('.' in t or '-' in t):
        reverse_morse = {code: char for char, code in MORSE.items()}
        words = t.split(' / ')
        decoded = [''.join(reverse_morse.get(part, '?') for part in word.split()) for word in words]
        if all('?' not in word for word in decoded):
            out.append(('morse', ' '.join(decoded).encode('ascii')))
    if len(t) >= 8 and not t.isspace():
        for label, fun in [('base85', base64.b85decode), ('ascii85', base64.a85decode)]:
            try:
                attempt = fun(t.encode('ascii'))
                if legibility(attempt) > .7 and len(attempt) >= 4:
                    out.append((label, attempt))
            except (ValueError, TypeError, UnicodeError, OverflowError):
                pass
    if len(t) >= 8 and re.search(r'[a-zA-Z]', t):
        rot = codecs.decode(t, 'rot_13')
        if rot != t:
            out.append(('rot13', rot.encode('utf-8', 'replace')))
        out.append(('reverse', t[::-1].encode('utf-8', 'replace')))
        atbash = t.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                                         'ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba'))
        if atbash != t:
            out.append(('atbash', atbash.encode('utf-8', 'replace')))
        # Caesar is meaningful for many short strings; don't flood a long PCAP dump.
        if len(t) <= 512:
            for shift in range(1, 26):
                def move(m):
                    c = m.group()
                    base = 65 if c.isupper() else 97
                    return chr((ord(c) - base + shift) % 26 + base)
                out.append((f'caesar+{shift}', re.sub('[a-zA-Z]', move, t).encode()))
    return [(method, data) for method, data in out if 0 < len(data) <= MAX_TEXT]


def decode_hunt(blob: bytes, pattern, max_depth=2, max_results=24):
    """Recursive, bounded decoding. Returns evidence with an explicit transformation chain."""
    start = blob[:MAX_TEXT]
    queue = deque([(start, [], 0)])
    seen = set()
    interesting = []
    findings = []
    while queue and len(seen) < MAX_STATES:
        current, chain, depth = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        hits = extract_flags(current, pattern)
        if chain and hits:
            for value in hits:
                findings.append({'value': value, 'chain': chain[:], 'preview': sample_text(current, 220)})
        if chain and legibility(current) >= .83 and len(interesting) < max_results:
            interesting.append({'method': ' → '.join(chain), 'preview': sample_text(current, 220), 'length': len(current), 'flags': hits})
        if depth >= max_depth:
            continue
        if depth <= 1 and len(current) < 1_000_000:
            unpacked = decompress_known(current, cap=200_000)
            if unpacked:
                method, out = unpacked
                queue.append((out, chain + [method + '-decompress'], depth + 1))
        if depth == 0:
            # Also scan tokens embedded in longer text, not just entire file.
            source = current.decode('latin-1', 'replace')
            snippets = [source[:4096]]
            for regex in [BASE64_TOKEN, HEX_TOKEN]:
                snippets.extend(m.group() for m in list(regex.finditer(source[:MAX_TEXT]))[:12])
        else:
            snippets = [current.decode('utf-8', 'replace')]
        for piece in snippets[:25]:
            # Avoid ROT13/reverse on massive unrelated binary blobs.
            if len(piece) > 4096:
                continue
            for operation, output in decoded_options(piece):
                if output not in seen:
                    queue.append((output, chain + [operation], depth + 1))
        # Single-byte XOR: attempt only in compact contexts, and keep matches only.
        if depth <= 1 and len(current) <= 4096:
            for key in range(1, 256):
                xored = bytes(b ^ key for b in current)
                for value in extract_flags(xored, pattern):
                    findings.append({'value': value, 'chain': chain + [f'xor 0x{key:02x}'], 'preview': sample_text(xored, 220)})
    distinct = []
    used = set()
    for item in findings:
        key = (item['value'], tuple(item['chain']))
        if key not in used:
            used.add(key)
            distinct.append(item)
    return distinct[:40], interesting[:max_results]


def decompress_known(data: bytes, cap=2_000_000):
    """Streaming decompression with a hard output cap (anti-zip-bomb)."""
    for name, wbits in [('gzip', 16 + zlib.MAX_WBITS), ('zlib', zlib.MAX_WBITS)]:
        try:
            decompressor = zlib.decompressobj(wbits)
            out = decompressor.decompress(data, cap + 1)
            if len(out) <= cap and decompressor.eof:
                return name, out
        except zlib.error:
            pass
    return None
