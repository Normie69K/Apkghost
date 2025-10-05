import os
import re
from .crypto_solver import try_decode_base64
from ..logger import logger

API_KEY_PATTERNS = [re.compile(p) for p in [r"AIza[0-9A-Za-z\-_]{35}", r"AKIA[0-9A-Z]{16}"]]
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
BASE64_RE = re.compile(r'([A-Za-z0-9+/]{20,})={0,2}')
CRYPTO_HINTS_RE = re.compile(r'Cipher\.getInstance\("(AES|RSA|DES)"\)', re.IGNORECASE)
DANGEROUS_PERMS = ["READ_SMS", "SEND_SMS", "READ_CONTACTS", "RECORD_AUDIO"]

def scan_project(decompiled_path):
    results = { "api_keys": [], "urls": [], "permissions": [], "decoded_strings": [], "crypto_hints": [], "scanned_files": 0 }
    for root, _, filenames in os.walk(decompiled_path):
        for fname in filenames:
            results["scanned_files"] += 1
            file_path = os.path.join(root, fname)
            if file_path.endswith(('.smali', '.xml', '.java', '.kt', '.js')):
                try:
                    with open(file_path, "r", errors="ignore") as fh:
                        txt = fh.read()
                        for pat in API_KEY_PATTERNS:
                            for m in pat.findall(txt): results["api_keys"].append({"file": fname, "match": m})
                        for u in URL_RE.findall(txt): results["urls"].append({"file": fname, "url": u})
                        for m in BASE64_RE.finditer(txt):
                            decoded = try_decode_base64(m.group(1))
                            if decoded: results["decoded_strings"].append({"file": fname, "encoded": m.group(1), "decoded": decoded.strip()})
                        for hint in CRYPTO_HINTS_RE.findall(txt):
                            if hint.upper() not in results["crypto_hints"]: results["crypto_hints"].append(hint.upper())
                except Exception as e:
                    logger.debug(f"Error reading {file_path}: {e}")
    manifest_path = os.path.join(decompiled_path, "AndroidManifest.xml")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", errors="ignore") as fh:
                mtxt = fh.read()
                for perm in DANGEROUS_PERMS:
                    if perm in mtxt and perm not in results["permissions"]: results["permissions"].append(perm)
        except Exception as e:
            logger.debug(f"Error reading manifest: {e}")
    return results