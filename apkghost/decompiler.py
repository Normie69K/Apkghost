import subprocess
import shlex
from .logger import logger

class Decompiler:
    """A dedicated class to handle the Apktool decompilation process."""
    def __init__(self, apk_path, output_dir):
        self.apk_path = apk_path
        self.output_dir = output_dir

    def run(self, timeout=900):
        cmd = f"apktool d {shlex.quote(self.apk_path)} -o {shlex.quote(self.output_dir)} -f"
        logger.info(f"Executing command: {cmd}")
        try:
            process = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            full_output = f"--- STDOUT ---\n{process.stdout}\n\n--- STDERR ---\n{process.stderr}"
            return {"success": process.returncode == 0, "output": full_output.strip()}
        except subprocess.TimeoutExpired:
            return {"success": False, "output": f"Timeout Error: Decompilation took longer than {timeout} seconds."}
        except Exception as e:
            return {"success": False, "output": f"An unexpected error occurred: {e}"}