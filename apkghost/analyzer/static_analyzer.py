import os, re
from ..logger import logger

API_KEY_PATTERNS = [
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),   # Google API key
    re.compile(r"AKIA[0-9A-Z]{16}"),         # AWS key-like
    re.compile(r"[0-9a-fA-F]{32,}"),         # long hex strings (generic)
    re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}")    # simple JWT-ish start (very rough)
]
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
POTENTIAL_CRED = re.compile(r"(password|passwd|pwd|secret|token)[\s:=\"']{1,3}([^\s\"']{4,100})", re.IGNORECASE)

SMALI_DIRS = ["smali", "smali_classes2", "smali_classes3", "smali_classes4", "smali_classes5"]

DANGEROUS_PERMS = [
    "READ_SMS", "SEND_SMS", "READ_CONTACTS", "RECORD_AUDIO",
    "READ_PHONE_STATE", "WRITE_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
]

def _gather_file_list(decompiled_path):
    files = []
    # walk everything (covers all layouts)
    for root, _, filenames in os.walk(decompiled_path):
        for fname in filenames:
            if fname.endswith(('.smali', '.xml', '.java', '.kt', '.js', '.json', '.txt')):
                files.append(os.path.join(root, fname))
    return files

def scan_strings_in_path(decompiled_path):
    results = {"api_keys": [], "urls": [], "credentials": [], "permissions": [], "scanned_files": 0}
    files = _gather_file_list(decompiled_path)
    results["scanned_files"] = len(files)

    for p in files:
        try:
            with open(p, "r", errors="ignore") as fh:
                txt = fh.read()
                # api keys
                for pat in API_KEY_PATTERNS:
                    for m in pat.findall(txt):
                        results["api_keys"].append({"file": p, "match": m})
                # urls
                for u in URL_RE.findall(txt):
                    results["urls"].append({"file": p, "url": u})
                # credentials-like patterns
                for cred in POTENTIAL_CRED.findall(txt):
                    # cred is tuple (label, value) from regex
                    results["credentials"].append({"file": p, "label": cred[0], "value": cred[1]})
        except Exception as e:
            logger.debug("read error %s: %s", p, e)

    # manifest check (look for AndroidManifest.xml anywhere under project)
    manifest_candidates = []
    for root, _, files in os.walk(decompiled_path):
        for f in files:
            if f == "AndroidManifest.xml":
                manifest_candidates.append(os.path.join(root, f))
    if manifest_candidates:
        # prefer root manifest
        manifest = manifest_candidates[0]
        try:
            with open(manifest, "r", errors="ignore") as fh:
                mtxt = fh.read()
                for perm in DANGEROUS_PERMS:
                    if perm in mtxt and perm not in results["permissions"]:
                        results["permissions"].append(perm)
        except Exception as e:
            logger.debug("manifest read error: %s", e)

    return results
