import os
import re
import xml.etree.ElementTree as ET
from ..logger import logger

API_KEY_PATTERNS = [re.compile(p) for p in [r"AIza[0-9A-Za-z\-_]{35}", r"AKIA[0-9A-Z]{16}"]]
URL_RE = re.compile(r"https?://[^\s\"'<>]+")

def scan_project(decompiled_path):
    """Runs all static analysis scans on the decompiled project folder."""
    results = {
        "api_keys": [], "urls": [], "permissions": [],
        "exported_activities": [], "deep_links": [], "scanned_files": 0
    }
    
    # --- Manifest Analysis for Activities and Deep Links ---
    manifest_path = os.path.join(decompiled_path, "AndroidManifest.xml")
    if os.path.exists(manifest_path):
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            app_tag = root.find('application')
            if app_tag:
                for activity in app_tag.findall('activity'):
                    name = activity.get(f"{{{ns['android']}}}name")
                    exported = activity.get(f"{{{ns['android']}}}exported")
                    if exported == "true":
                        results["exported_activities"].append(name)
                    
                    for intent_filter in activity.findall('intent-filter'):
                        has_action_view = intent_filter.find('action') is not None and intent_filter.find('action').get(f"{{{ns['android']}}}name") == 'android.intent.action.VIEW'
                        has_category_browsable = intent_filter.find('category') is not None and intent_filter.find('category').get(f"{{{ns['android']}}}name") == 'android.intent.category.BROWSABLE'
                        if has_action_view and has_category_browsable:
                            for data in intent_filter.findall('data'):
                                scheme = data.get(f"{{{ns['android']}}}scheme")
                                host = data.get(f"{{{ns['android']}}}host")
                                if scheme and host:
                                    results["deep_links"].append(f"{scheme}://{host}")
        except Exception as e:
            logger.error(f"Failed to parse AndroidManifest.xml: {e}")

    # --- File Content Scanning ---
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
                except Exception:
                    pass
            
    return results