import subprocess, shlex
from .config import APKTOOL_CMD, JADX_CMD
from .logger import logger

def run_apktool_decompile(apk_path, out_dir, timeout=600):
    cmd = f"{APKTOOL_CMD} d {shlex.quote(apk_path)} -o {shlex.quote(out_dir)} -f"
    logger.info("Decompile cmd: %s", cmd)
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr

def run_apktool_build(proj_dir, out_apk, timeout=600):
    cmd = f"{APKTOOL_CMD} b {shlex.quote(proj_dir)} -o {shlex.quote(out_apk)}"
    logger.info("Build cmd: %s", cmd)
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr

def run_jadx(apk_path, out_dir, timeout=600):
    cmd = f"{JADX_CMD} -d {shlex.quote(out_dir)} {shlex.quote(apk_path)}"
    logger.info("JADX cmd: %s", cmd)
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr
