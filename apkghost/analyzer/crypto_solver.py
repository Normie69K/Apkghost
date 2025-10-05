import base64
import re

def is_meaningful_ascii(s):
    if not all(32 <= ord(c) < 127 for c in s.strip()):
        return False
    if len(s.strip()) > 10 and len(set(s.strip())) < 5:
        return False
    if re.search(r'[a-zA-Z]{3,}', s) and re.search(r'[\s\.:,=\-_\(\)\[\]\{\}]', s):
        return True
    if len(s.strip()) > 8 and s.replace(' ', '').isalpha():
        return True
    return False

def try_decode_base64(encoded_str):
    try:
        padding = len(encoded_str) % 4
        if padding: encoded_str += "=" * (4 - padding)
        decoded_bytes = base64.b64decode(encoded_str, validate=True)
        decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
        if len(decoded_str.strip()) > 8 and is_meaningful_ascii(decoded_str):
            return decoded_str
    except Exception:
        pass
    return None

def try_decode_hex(encoded_str):
    try:
        if len(encoded_str) > 8 and len(encoded_str) % 2 == 0:
            decoded_bytes = bytes.fromhex(encoded_str)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            if len(decoded_str.strip()) > 8 and is_meaningful_ascii(decoded_str):
                return decoded_str
    except Exception:
        pass
    return None