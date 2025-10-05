import os
from PIL import Image, ExifTags
import pefile

def get_string_dump(file_path):
    strings = []
    try:
        with open(file_path, "rb") as f: data = f.read()
        current_string = ""
        for byte in data:
            if 32 <= byte < 127: current_string += chr(byte)
            else:
                if len(current_string) >= 5: strings.append(current_string)
                current_string = ""
        if len(current_string) >= 5: strings.append(current_string)
    except Exception as e:
        return [f"Error reading file: {e}"]
    return strings

def inspect_file(file_path):
    report = [f"### Analysis for: {os.path.basename(file_path)} ###\n"]
    file_ext = os.path.splitext(file_path)[1].lower()
    try:
        if file_ext in ['.png', '.jpg', '.jpeg', '.gif', '.webp']:
            img = Image.open(file_path)
            report.append(f"Type: Image ({img.format})"); report.append(f"Size: {img.width}x{img.height}"); report.append(f"Mode: {img.mode}")
            if hasattr(img, '_getexif') and img._getexif():
                exif = {ExifTags.TAGS.get(t, t): v for t, v in img._getexif().items()}
                if exif:
                    report.append("\n--- EXIF Data ---")
                    for tag, val in exif.items(): report.append(f"  {tag}: {val}")
        elif file_ext == '.pdf':
            report.append("Type: PDF Document\n--- String Dump (first 100) ---")
            for s in get_string_dump(file_path)[:100]: report.append(f"  - {s}")
        elif file_ext in ['.exe', '.dll']:
            pe = pefile.PE(file_path)
            report.append(f"Type: PE Executable ({'DLL' if pe.is_dll() else 'EXE'})")
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                report.append("\n--- Imported DLLs ---")
                for entry in pe.DIRECTORY_ENTRY_IMPORT: report.append(f"  - {entry.dll.decode()}")
        else:
            report.append("Type: Generic Binary/Text File\n--- String Dump (first 100) ---")
            strings = get_string_dump(file_path)
            for s in strings[:100]: report.append(f"  - {s}")
            if len(strings) > 100: report.append(f"\n... and {len(strings) - 100} more.")
    except Exception as e:
        report.append(f"\n--- ERROR: {e} ---")
    return "\n".join(report)