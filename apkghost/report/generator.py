import json
import os
from ..utils import ensure_dir # Corrected import path
from ..logger import logger

def save_json_report(results, out_path):
    try:
        ensure_dir(os.path.dirname(out_path) or '.')
        with open(out_path, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info("Saved JSON report: %s", out_path)
        return out_path
    except Exception as e:
        logger.exception("Failed to write report: %s", e)
        return None

def save_html_report(results, out_path, template=None):
    try:
        ensure_dir(os.path.dirname(out_path) or '.')
        # Very simple HTML report, can be improved
        with open(out_path, 'w') as f:
            f.write("<html><head><meta charset='utf-8'><title>APK Ghost Report</title></head><body>")
            f.write("<h1>APK Ghost Analysis Report</h1>")
            f.write("<pre>")
            f.write(json.dumps(results, indent=2))
            f.write("</pre></body></html>")
        logger.info("Saved HTML report: %s", out_path)
        return out_path
    except Exception as e:
        logger.exception("Failed to write html report: %s", e)
        return None