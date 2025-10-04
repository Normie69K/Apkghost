import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading, os
from .tools_integration import run_apktool_decompile, run_apktool_build, run_jadx
from .analyzer.static_analyzer import scan_strings_in_path
from .report.generator import save_json_report
from .logger import logger

class Controller:
    def __init__(self, app):
        self.app = app
        self._build_ui()

    def _build_ui(self):
        top = ctk.CTkFrame(self.app)
        top.pack(fill='x', padx=10, pady=10)
        self.extract_btn = ctk.CTkButton(top, text="Extract APK", command=self.on_extract)
        self.extract_btn.pack(side='left', padx=8)
        self.analyze_btn = ctk.CTkButton(top, text="Analyze Project", command=self.on_analyze)
        self.analyze_btn.pack(side='left', padx=8)
        self.build_btn = ctk.CTkButton(top, text="Build APK", command=self.on_build)
        self.build_btn.pack(side='left', padx=8)

        self.status = ctk.CTkLabel(self.app, text="Idle")
        self.status.pack(fill='x', padx=10)

        self.logbox = ctk.CTkTextbox(self.app, width=980, height=520)
        self.logbox.pack(padx=10, pady=10)

    def log(self, msg):
        self.logbox.insert("end", msg + "\n")
        self.logbox.see("end")

    def _analyze_job(self, proj):
        self._log(f"Analyzing {proj}")
        self.progressbar.set(0.3)
        try:
            res = scan_strings_in_path(proj)
            saved = save_json_report(res, os.path.join(proj, "analysis_report.json"))
            self._log(f"Scanned files: {res.get('scanned_files', 0)}")
            self._log(f"API Keys found: {len(res.get('api_keys', []))}")
            self._log(f"URLs found: {len(res.get('urls', []))}")
            self._log(f"Credentials-like matches: {len(res.get('credentials', []))}")
            self._log(f"Permissions flagged: {res.get('permissions')}")
            self._log(f"Report saved: {saved}")
            self.status.configure(text="Analysis complete ✔")
        except Exception as e:
            self._log(f"Analysis error: {e}")
            self.status.configure(text="Analysis error")
        finally:
            self.progressbar.set(1)


    def on_extract(self):
        apk = filedialog.askopenfilename(filetypes=[("APK files","*.apk")])
        if not apk: return
        out = filedialog.askdirectory(title="Select output directory") or os.path.dirname(apk)
        self.status.configure(text="Decompiling...")
        def job():
            code, txt = run_apktool_decompile(apk, out)
            self.log(txt)
            self.status.configure(text="Done" if code==0 else "Failed")
        threading.Thread(target=job).start()

    def on_analyze(self):
        proj = filedialog.askdirectory(title="Select Decompiled Project")
        if not proj: return
        self.status.configure(text="Analyzing...")
        def job():
            res = scan_strings_in_path(proj)
            saved = save_json_report(res, os.path.join(proj, "analysis_report.json"))
            self.log(f"Analysis saved to: {saved}")
            self.status.configure(text="Analysis complete")
        threading.Thread(target=job).start()

    def on_build(self):
        proj = filedialog.askdirectory(title="Select Decompiled Project")
        if not proj: return
        out = filedialog.asksaveasfilename(defaultextension=".apk", filetypes=[("APK","*.apk")])
        if not out: return
        self.status.configure(text="Building APK...")
        def job():
            code, txt = run_apktool_build(proj, out)
            self.log(txt)
            self.status.configure(text="Built" if code==0 else "Failed")
        threading.Thread(target=job).start()


        
