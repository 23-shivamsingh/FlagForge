"""Question-aware offline CTF hunting passes.

All operations consume previously saved evidence; no capture or network access.
Every lead is an observation/hypothesis, never a fabricated solution.
"""
from __future__ import annotations
import collections
import re
from dataclasses import dataclass

MAX_DNS_GROUPS = 20
MAX_COVERT = 70_000

INTENTS = {
    'dns': ('dns','domain','subdomain','txt record','exfil','exfiltration','queries','dns tunnel'),
    'http': ('http','https','request','response','cookie','header','user agent','web','upload','download'),
    'streams': ('tcp','stream','conversation','payload','fragment','packet','follow'),
    'metadata': ('metadata','comment','hidden text','hidden message','information','header','sni','certificate'),
    'files': ('file','image','picture','document','transferred','attachment','object','extract','zip'),
    'keyboard': ('keyboard','usb','keystroke','typing','hid','key press'),
    'encoding': ('base64','base32','hex','encoded','decode','cipher','xor','encrypted','rot13'),
    'covert': ('icmp','ping','timing','size','length','covert','tunnel','ttl'),
}


def challenge_intents(question: str) -> list[str]:
    q = question.lower()[:3000]
    matches = [(key, sum(len(re.findall(r'(?<![a-z0-9])' + re.escape(word) + r'(?![a-z0-9])', q)) for word in words))
               for key, words in INTENTS.items()]
    return [name for name, score in sorted(matches, key=lambda x: -x[1]) if score]


def investigation_plan(question: str, cap: dict | None, flags: list[dict], artifacts: list[dict]):
    """Explainable, deterministic decisions; question is not executed as code."""
    intent = challenge_intents(question)
    steps = []
    if not cap:
        steps.append({'kind': 'inspect', 'title': 'Inspect source material', 'detail': 'Scan file bytes, metadata, printable strings and embedded encodings.', 'priority': 'high'})
    else:
        counts = {p['name']: p['count'] for p in cap['protocols']}
        if cap.get('dns') or 'dns' in intent:
            steps.append({'kind': 'dns', 'title': 'Reassemble DNS fragments', 'detail': 'Check TXT answers, query labels, sequence-indexed domains and encoded exfiltration.', 'priority': 'high' if 'dns' in intent else 'medium'})
        if cap.get('http') or 'http' in intent:
            steps.append({'kind': 'http', 'title': 'Inspect HTTP conversations', 'detail': 'Review URLs, headers/cookies, transferred bodies, chunking and compression.', 'priority': 'high' if 'http' in intent else 'medium'})
        if cap.get('streams'):
            steps.append({'kind': 'tcp', 'title': 'Follow reconstructed streams', 'detail': 'Inspect both directions and look for truncated/gapped streams, hidden tokens and embedded files.', 'priority': 'high' if 'streams' in intent else 'medium'})
        if counts.get('ICMP', 0) or 'covert' in intent:
            steps.append({'kind': 'covert', 'title': 'Examine ICMP covert channels', 'detail': 'Inspect ICMP payloads, identifier patterns and possible one-character-per-packet signals.', 'priority': 'high' if 'covert' in intent else 'medium'})
        if 'keyboard' in intent:
            steps.append({'kind': 'usb', 'title': 'Recover USB HID keystrokes', 'detail': 'With TShark installed, attempt USB keyboard report extraction and replay.', 'priority': 'high'})
        if cap.get('tls'):
            steps.append({'kind': 'tls', 'title': 'Inspect TLS handshakes', 'detail': 'TLS SNI names are visible, but application plaintext requires legitimate key material.', 'priority': 'medium'})
    if not flags:
        steps.append({'kind': 'decode', 'title': 'Search for non-obvious flag formats', 'detail': 'Try the event-specific flag prefix, inspect decoded trails and locally ask AI about unresolved clues.', 'priority': 'high'})
    else:
        steps.insert(0, {'kind': 'candidate', 'title': 'Validate top candidate', 'detail': 'Copy the exact bytes, inspect its source and submit only to the challenge scoreboard.', 'priority': 'high'})
    if artifacts:
        steps.append({'kind': 'file', 'title': 'Inspect recovered objects', 'detail': 'Extracted objects are recursively scanned. Download and review any unsupported format safely.', 'priority': 'medium'})
    return {'question': question[:1200], 'intents': intent,
            'steps': steps[:12], 'automatic_flag_verification': False}


def rank_flags(flags: list[dict], question: str):
    intent = challenge_intents(question)
    for flag in flags:
        score = 70 if flag['method'] == 'direct' else 60
        reasons = ['Exact flag-pattern match'] if flag['method'] == 'direct' else ['Decoded with a reproducible transformation chain']
        if len(flag.get('sources', [])) > 1:
            score += min(12, 4 * (len(flag['sources']) - 1))
            reasons.append('Observed in multiple evidence locations')
        source = (' '.join(flag.get('sources', [flag['source']]))).lower()
        for kind in intent:
            terms = {'dns': ('dns',), 'http': ('http', 'cookie', 'headers'), 'streams': ('tcp', 'udp', 'stream'),
                     'metadata': ('meta', 'exif', 'comment', 'sni'), 'files': ('body','zip','artifact','image'),
                     'keyboard': ('keyboard','usb','hid'), 'encoding': ('encoded','decoded','base64','hex'),
                     'covert': ('icmp','covert','ping')}.get(kind, ())
            if any(word in source for word in terms):
                score += 8
                reasons.append('Matches challenge topic: '+kind)
                break
        # Quality of evidence, not probability of scoreboard acceptance.
        flag['score'] = min(score, 99)
        flag['reasons'] = reasons
        flag['verified'] = False
    flags.sort(key=lambda x: (-x['score'], x['value']))


def dns_reconstructions(records: list[dict]):
    """Returns source-labelled byte strings from multi-query DNS exfil patterns.

    Supports order-of-appearance and common 0001.fragment.domain sequence formats.
    Does not assume that all QNAMEs contain malicious data.
    """
    answers = []
    txt = [r.get('value', '') for r in records if r.get('kind') == 'TXT' and r.get('value')]
    if len(txt) >= 2:
        answers.append(('DNS multi-answer TXT concatenation', ''.join(txt).encode()))
    queries = [r['name'] for r in records if r.get('kind') == 'query' and r.get('name')]
    groups = collections.defaultdict(list)
    for order, domain in enumerate(queries[:300]):
        labels = domain.rstrip('.').split('.')
        if len(labels) < 3:
            continue
        suffix = '.'.join(labels[-2:]).lower()
        payload = labels[:-2]
        if not payload:
            continue
        index = None
        if re.fullmatch(r'\d{1,5}', payload[0]):
            index = int(payload.pop(0))
        elif re.fullmatch(r'\d{1,5}', payload[-1]):
            index = int(payload.pop())
        group_piece = ''.join(payload)
        if not group_piece or len(group_piece) > 250:
            continue
        groups[suffix].append((index, order, group_piece))
    for domain, chunks in sorted(groups.items(), key=lambda item: -len(item[1]))[:MAX_DNS_GROUPS]:
        if len(chunks) < 2:
            continue
        unique = list(dict.fromkeys((idx, idx2, piece) for idx,idx2,piece in chunks))
        indexed = sum(index is not None for index,_,_ in unique) >= len(unique)//2 + 1
        if indexed:
            unique.sort(key=lambda x: (x[0] is None, x[0] if x[0] is not None else x[1]))
        joined = ''.join(x[2] for x in unique)
        if len(joined) > MAX_COVERT:
            joined = joined[:MAX_COVERT]
        if len(joined) >= 12:
            answers.append((f'DNS label reassembly / {domain} / {"sequence index" if indexed else "capture order"}', joined.encode()))
    return answers[:20]


def tls_sni(data: bytes) -> list[str]:
    """Extract cleartext SNI from bounded TLS ClientHello records (not decryption)."""
    hits = []
    for start in [m.start() for m in list(re.finditer(rb'\x16\x03[\x00-\x04]', data[:100_000]))[:16]]:
        if start + 9 > len(data): continue
        end = start + 5 + int.from_bytes(data[start+3:start+5], 'big')
        if end > min(len(data), start + 32768) or data[start+5] != 1: continue
        body = data[start+9:end]
        try:
            # version(2) + random(32) + session_id + cipher suites + compression + extensions
            pos = 34
            session = body[pos]; pos += 1 + session
            suite_length = int.from_bytes(body[pos:pos+2], 'big'); pos += 2 + suite_length
            compression_length = body[pos]; pos += 1 + compression_length
            ext_len = int.from_bytes(body[pos:pos+2], 'big'); pos += 2
            ext_end = min(pos + ext_len, len(body))
            while pos + 4 <= ext_end:
                typ = int.from_bytes(body[pos:pos+2], 'big')
                size = int.from_bytes(body[pos+2:pos+4], 'big')
                value = body[pos+4:pos+4+size]
                pos += 4+size
                if typ != 0 or len(value) < 5: continue
                list_len = int.from_bytes(value[:2], 'big')
                if list_len + 2 > len(value): continue
                if value[2] != 0: continue
                n = int.from_bytes(value[3:5], 'big')
                hostname = value[5:5+n].decode('ascii', 'ignore')
                if len(hostname) >= 3 and re.fullmatch(r'[A-Za-z0-9.-]+', hostname):
                    hits.append(hostname[:255])
        except (IndexError, ValueError):
            continue
    return list(dict.fromkeys(hits))[:20]


# USB boot keyboard standard US layout; non-US keyboards differ.
HID_KEYS = {**{i+4:ch for i,ch in enumerate('abcdefghijklmnopqrstuvwxyz')},
            **{i+30:ch for i,ch in enumerate('1234567890')},
            40:'\n', 41:'[ESC]', 42:'\b', 43:'\t', 44:' ', 45:'-', 46:'=', 47:'[', 48:']',
            49:'\\', 51:';', 52:"'", 53:'`', 54:',', 55:'.', 56:'/'}
SHIFT_KEYS = dict(zip('1234567890-=[]\\;\'`,./', '!@#$%^&*()_+{}|:"~<>?'))


def recover_hid_keystrokes(reports: list[bytes]) -> str:
    """Replay 8-byte USB boot keyboard reports with repeat suppression and backspace."""
    chars = []
    previous = set()
    for report in reports[:15000]:
        if len(report) != 8: continue
        shift = bool(report[0] & 0x22)
        pressed = set(k for k in report[2:8] if k >= 4)
        for key in report[2:8]:
            if key < 4 or key in previous: continue
            value = HID_KEYS.get(key)
            if not value: continue
            if value == '\b':
                if chars: chars.pop()
            elif value == '[ESC]':
                continue
            elif shift:
                chars.append(SHIFT_KEYS.get(value, value.upper()))
            else:
                chars.append(value)
            if len(chars) >= 6000: break
        previous = pressed
        if len(chars) >= 6000: break
    return ''.join(chars)
