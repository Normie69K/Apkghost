import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
APKTOOL_CMD = os.environ.get("APKTOOL_CMD", "apktool")
JADX_CMD = os.environ.get("JADX_CMD", "jadx")
VT_API_KEY = os.environ.get("VT_API_KEY", "")
