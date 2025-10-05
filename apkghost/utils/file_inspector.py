import os
import pefile
from PIL import Image, ExifTags

def generate_hex_view(file_path):
    try:
        with open(file_path, 'rb') as f:
            offset = 0
            while True:
                chunk = f.read(16)
                if not chunk: break
                offset_str = f'{offset:08x}'
                hex_str = ' '.join(f'{b:02x}' for b in chunk).ljust(16 * 3 - 1)
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                yield f'{offset_str}  {hex_str}  |{ascii_str}|\n'
                offset += 16
    except Exception as e:
        yield f"Error reading file: {e}\n"

def inspect_file_metadata(file_path):
    report = [f"### Metadata for: {os.path.basename(file_path)} ###\n"]
    ext = os.path.splitext(file_path)[1].lower()
    try:
        if ext in ['.png', '.jpg', '.jpeg', '.gif']:
            with Image.open(file_path) as img: report.append(f"Type: Image ({img.format}), Size: {img.width}x{img.height}")
        elif ext in ['.exe', '.dll']:
            pe = pefile.PE(file_path)
            report.append(f"Type: PE Executable ({'DLL' if pe.is_dll() else 'EXE'})")
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                report.append("\n--- Imported DLLs ---")
                for entry in pe.DIRECTORY_ENTRY_IMPORT: report.append(f"  - {entry.dll.decode()}")
        else:
            report.append("No specific metadata extractor for this file type.")
    except Exception as e:
        report.append(f"\n--- Metadata Error: {e} ---")
    return "\n".join(report)