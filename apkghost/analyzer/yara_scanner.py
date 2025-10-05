import yara
import os
from ..logger import logger

def run_yara_scan(scan_path, rules_path):
    """Scans a directory with a given YARA rules file."""
    if not os.path.exists(rules_path):
        return {"error": f"YARA rules file not found: {rules_path}"}
    if not os.path.isdir(scan_path):
        return {"error": f"Scan directory not found: {scan_path}"}
        
    try:
        rules = yara.compile(filepath=rules_path)
    except yara.Error as e:
        return {"error": f"YARA compilation failed: {e}"}

    matches = []
    logger.info(f"Starting YARA scan on {scan_path}")
    for root, _, files in os.walk(scan_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                yara_matches = rules.match(filepath=file_path)
                if yara_matches:
                    for match in yara_matches:
                        matches.append(f"Rule '{match.rule}' matched in file: {file_path}")
            except yara.Error:
                continue # Skip files that can't be read
    
    logger.info(f"YARA scan finished. Found {len(matches)} matches.")
    return {"matches": matches}