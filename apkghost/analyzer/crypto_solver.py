import base64
import re

def is_meaningful_ascii(s):
    s = s.strip()
    if not s or not all(32 <= ord(c) < 127 for c in s):
        return False
    if len(s) > 10 and len(set(s)) < 4:
        return False
    if re.search(r'[\s\.:,=\-_\(\)\[\]\{\}]', s):
        return True
    if re.search(r'\b(is|am|are|the|and|for|not)\b', s, re.IGNORECASE):
        return True
    return False

def try_decode_base64(encoded_str):
    try:
        padding = len(encoded_str) % 4
        if padding: encoded_str += "=" * (4 - padding)
        decoded_bytes = base64.b64decode(encoded_str, validate=True)
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
        if is_meaningful_ascii(decoded_str):
            return decoded_str
    except Exception:
        pass
    return None