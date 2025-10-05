import subprocess
import shlex
import os
from androguard.session import Session
from .logger import logger

def decompile_with_apktool(apk_path, output_dir, timeout=900):
    cmd = f"apktool d {shlex.quote(apk_path)} -o {shlex.quote(output_dir)} -f"
    logger.info(f"Executing command: {cmd}")
    try:
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        full_output = f"--- STDOUT ---\n{process.stdout}\n\n--- STDERR ---\n{process.stderr}"
        return {"success": process.returncode == 0, "output": full_output.strip()}
    except Exception as e:
        return {"success": False, "output": f"An unexpected error occurred: {e}"}

def decompile_with_androguard(apk_path, output_dir):
    logger.info(f"Decompiling with Androguard: {apk_path}")
    try:
        s = Session();
        with open(apk_path, "rb") as f: s.add(apk_path, f.read())
        for f_path in s.get_files():
            out_path = os.path.join(output_dir, *f_path.split(os.sep))
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "wb") as fp: fp.write(s.get_file(f_path))
        return {"success": True, "output": "Androguard decompilation successful."}
    except Exception as e:
        return {"success": False, "output": f"Androguard Error: {e}"}

def run_apktool_decompile(apk_path, out_dir, timeout=600):
    """Legacy wrapper for CLI compatibility."""
    result = decompile_with_apktool(apk_path, out_dir, timeout)
    return 0 if result["success"] else 1, result["output"]