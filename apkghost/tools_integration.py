import subprocess
import shlex
# Corrected the import path below for modern Androguard versions
from androguard.core.apk import APK
from .logger import logger

def decompile_with_apktool(apk_path, out_dir, timeout=900):
    """Runs the external Apktool command."""
    cmd = f"apktool d {shlex.quote(apk_path)} -o {shlex.quote(out_dir)} -f"
    logger.info(f"Executing command: {cmd}")
    try:
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        full_output = f"--- STDOUT ---\n{process.stdout}\n\n--- STDERR ---\n{process.stderr}"
        return {"success": process.returncode == 0, "output": full_output.strip()}
    except Exception as e:
        return {"success": False, "output": f"An unexpected error occurred: {e}"}

def decompile_with_androguard(apk_path, out_dir, timeout=900):
    """Decompiles the APK using Androguard."""
    logger.info(f"Decompiling {apk_path} with Androguard")
    try:
        from androguard.decompiler.decompiler import DecompilerJADX
        from androguard.core.analysis.analysis import Analysis
        from androguard.core.bytecodes.dvm import DalvikVMFormat
        
        apk = APK(apk_path)
        dvm = DalvikVMFormat(apk.get_dex())
        dx = Analysis(dvm)
        dx.create_xref()
        
        # Androguard does not decompile to a directory structure like apktool.
        # This is a simplified representation. For a full-featured alternative,
        # you would iterate through classes and methods and write them to files.
        with open(f"{out_dir}/androguard_analysis.txt", "w") as f:
            for cls in dvm.get_classes():
                f.write(f"Class: {cls.name}\n")
                for method in cls.get_methods():
                    f.write(f"  Method: {method.name}\n")
                    
        return {"success": True, "output": f"Androguard analysis written to {out_dir}/androguard_analysis.txt"}
    except Exception as e:
        logger.exception("Androguard decompilation failed.")
        return {"success": False, "output": f"Error during Androguard decompilation: {e}"}


def analyze_signature(apk_path):
    """Analyzes the APK's signature and certificate using Androguard."""
    logger.info(f"Analyzing signature for {apk_path}")
    report = []
    try:
        apk = APK(apk_path)
        report.append("--- Certificate Details ---")
        if not apk.is_signed():
            report.append("[!] APK is not signed.")
            return "\n".join(report)

        for cert in apk.get_certificates():
            report.append(f"Issuer: {cert.issuer.human_friendly}")
            report.append(f"Subject: {cert.subject.human_friendly}")
            report.append(f"Serial Number: {cert.serial_number}")
            report.append(f"Signature Algorithm: {cert.signature_algorithm_oid._name}")
            report.append(f"Valid From: {cert.not_valid_before}")
            report.append(f"Valid Until: {cert.not_valid_after}")
        return "\n".join(report)
    except Exception as e:
        logger.exception("Signature analysis failed.")
        return f"Error during signature analysis: {e}"