#!/usr/bin/env bash
# Quick environment preflight (prints binary versions if present)
echo "Checking environment..."
command -v java && java -version 2>&1 || echo "java not found"
command -v apktool >/dev/null 2>&1 && echo "apktool found" || echo "apktool not found in PATH"
command -v jadx >/dev/null 2>&1 && echo "jadx found" || echo "jadx not found in PATH"
command -v adb >/dev/null 2>&1 && echo "adb found" || echo "adb not found in PATH"
