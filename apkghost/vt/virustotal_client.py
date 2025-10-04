import os, requests
from ..logger import logger
from ..config import VT_API_KEY

BASE = "https://www.virustotal.com/api/v3"

def lookup_file_hash(sha256):
    if not VT_API_KEY:
        logger.warning("VT_API_KEY not set; skipping VirusTotal lookup")
        return None
    headers = {"x-apikey": VT_API_KEY}
    url = f"{BASE}/files/{sha256}"
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        return r.json()
    else:
        logger.warning("VT lookup failed: %s", r.status_code)
        return None
