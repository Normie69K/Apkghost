#!/usr/bin/env python3
import shutil, sys
missing = []
for cmd in ["java", "apktool", "jadx"]:
    if shutil.which(cmd) is None:
        missing.append(cmd)
if missing:
    print("Missing required binaries:", ", ".join(missing))
    print("Install them and make sure they are in PATH.")
    sys.exit(1)
print("Preflight checks passed.")
