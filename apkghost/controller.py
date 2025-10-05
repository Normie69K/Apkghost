import customtkinter as ctk
from tkinter import filedialog, ttk
import threading
import os
import html
from .tools_integration import decompile_with_apktool, decompile_with_androguard
from .analyzer.static_analyzer import scan_project
from .utils.file_inspector import inspect_file_metadata, generate_hex_view
from .logger import logger
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT

class Controller:
    def __init__(self, app):
        self.app = app; self.apk_path = None; self.output_dir = None; self.report_text = ""
        self.inspected_file_path = None
        self._build_responsive_ui()

    def _build_responsive_ui(self):
        self.app.grid_rowconfigure(0, weight=1); self.app.grid_columnconfigure(0, weight=1)
        self.tab_view = ctk.CTkTabview(self.app, fg_color="#2B2B2B"); self.tab_view.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.tab_view.add("APK Analyzer"); self.tab_view.add("File Inspector")
        self._build_apk_analyzer_tab(self.tab_view.tab("APK Analyzer"))
        self._build_file_inspector_tab(self.tab_view.tab("File Inspector"))

    def _build_apk_analyzer_tab(self, tab):
        tab.grid_rowconfigure(1, weight=1); tab.grid_columnconfigure(0, weight=1)
        control_frame = ctk.CTkFrame(tab, fg_color="transparent"); control_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        control_frame.grid_columnconfigure(1, weight=1)
        self.select_apk_btn=ctk.CTkButton(control_frame, text="Select APK", command=self.on_select_apk); self.select_apk_btn.grid(row=0, column=0, padx=(0, 10))
        self.apk_path_label=ctk.CTkLabel(control_frame, text="No APK selected...", anchor="w", fg_color="#333333", corner_radius=6, padx=10); self.apk_path_label.grid(row=0, column=1, sticky="ew")
        self.select_out_btn=ctk.CTkButton(control_frame, text="Select Output", command=self.on_select_output); self.select_out_btn.grid(row=1, column=0, padx=(0, 10), pady=(10, 0))
        self.out_path_label=ctk.CTkLabel(control_frame, text="No output directory...", anchor="w", fg_color="#333333", corner_radius=6, padx=10); self.out_path_label.grid(row=1, column=1, sticky="ew", pady=(10, 0))
        self.engine_var = ctk.StringVar(value="apktool"); ctk.CTkOptionMenu(control_frame, variable=self.engine_var, values=["apktool", "androguard"]).grid(row=0, column=2, padx=(20,10))
        self.analyze_btn=ctk.CTkButton(control_frame, text="Decompile & Analyze", fg_color="green", state="disabled", command=self.on_analyze); self.analyze_btn.grid(row=1, column=2, padx=(20, 0), pady=(10, 0), ipady=10, sticky="ew")
        main_frame=ctk.CTkFrame(tab); main_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew"); main_frame.grid_rowconfigure(0, weight=1); main_frame.grid_columnconfigure(0, weight=1, minsize=250); main_frame.grid_columnconfigure(1, weight=3)
        self.file_tree=self.create_treeview(main_frame); self.file_tree.grid(row=0, column=0, sticky="nsew")
        self.code_preview=ctk.CTkTextbox(main_frame, font=("monospace", 12), wrap="none"); self.code_preview.grid(row=0, column=1, padx=(10, 0), sticky="nsew"); self.file_tree.bind("<<TreeviewSelect>>", self.on_file_select)
        bottom_frame = ctk.CTkFrame(tab, fg_color="transparent"); bottom_frame.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew"); bottom_frame.grid_columnconfigure(0, weight=1)
        self.status_label=ctk.CTkLabel(bottom_frame, text="Idle"); self.status_label.grid(row=0, column=0, sticky="w")
        self.export_btn=ctk.CTkButton(bottom_frame, text="Export as PDF", state="disabled", command=self.on_export_pdf); self.export_btn.grid(row=0, column=1, sticky="e")
        self.log_box=ctk.CTkTextbox(bottom_frame, height=100); self.log_box.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(5,0))

    def _build_file_inspector_tab(self, tab):
        tab.grid_rowconfigure(2, weight=1); tab.grid_columnconfigure(0, weight=1)
        controls = ctk.CTkFrame(tab, fg_color="transparent"); controls.grid(row=0, column=0, padx=20, pady=10, sticky="ew"); controls.grid_columnconfigure(1, weight=1)
        ctk.CTkButton(controls, text="Select File", command=self.on_inspect_file).grid(row=0, column=0, padx=(0, 20))
        self.search_entry = ctk.CTkEntry(controls, placeholder_text="Search text..."); self.search_entry.grid(row=0, column=1, padx=(0, 10), sticky="ew")
        self.search_btn = ctk.CTkButton(controls, text="Search", width=100, command=self.on_hex_search, state="disabled"); self.search_btn.grid(row=0, column=2)
        self.metadata_view = ctk.CTkTextbox(tab, font=("monospace", 13), height=120); self.metadata_view.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="nsew")
        self.inspector_view = ctk.CTkTextbox(tab, font=("monospace", 11), wrap="none"); self.inspector_view.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.inspector_view.tag_config("highlight", background="yellow", foreground="black")

    def create_treeview(self, parent):
        style = ttk.Style(); style.theme_use("default"); style.configure("Treeview", background="#2B2B2B", foreground="white", fieldbackground="#2B2B2B", borderwidth=0); style.map('Treeview', background=[('selected', '#1F6AA5')]); return ttk.Treeview(parent, show="tree")

    def on_file_select(self, event):
        s = self.file_tree.focus()
        if not s: return
        p = self.file_tree.item(s)["values"][0]; self.code_preview.delete("1.0", "end")
        if os.path.isfile(p):
            try:
                with open(p, "r", errors="ignore") as f: self.code_preview.insert("1.0", f.read(1024*100))
            except Exception as e: self.code_preview.insert("1.0", f"Error: {e}")

    def on_select_apk(self):
        p = filedialog.askopenfilename(filetypes=[("Android Package", "*.apk")]);
        if p: self.apk_path=p; self.apk_path_label.configure(text=p); self.check_button_states()

    def on_select_output(self):
        p = filedialog.askdirectory(title="Select folder for decompiled project");
        if p: self.output_dir=p; self.out_path_label.configure(text=p); self.check_button_states()

    def on_analyze(self):
        self.file_tree.delete(*self.file_tree.get_children()); self.code_preview.delete("1.0", "end"); self.export_btn.configure(state="disabled")
        threading.Thread(target=self._analysis_job, daemon=True).start()

    def on_export_pdf(self):
        p = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Documents", "*.pdf")])
        if not p: return
        try:
            doc = SimpleDocTemplate(p); s = getSampleStyleSheet(); s.add(ParagraphStyle(name='CodeSmall', parent=s['Code'], fontSize=8, leading=10))
            story = [Paragraph("Apkghost Report", s['h1'])]
            clean_report = html.escape(self.report_text).replace("\n", "<br/>")
            story.append(Paragraph(clean_report, s['CodeSmall']))
            doc.build(story); self.log(f"Report exported to {p}")
        except Exception as e: self.log(f"Failed to export PDF: {e}")

    def on_inspect_file(self):
        p = filedialog.askopenfilename(title="Select any file");
        if not p: return
        self.inspected_file_path = p; self.inspector_view.delete("1.0", "end"); self.metadata_view.delete("1.0", "end")
        self.set_status(f"Inspecting..."); self.tab_view.set("File Inspector")
        self.search_btn.configure(state="normal")
        threading.Thread(target=self._inspect_job, args=(p,), daemon=True).start()

    def on_hex_search(self):
        t = self.search_entry.get()
        if not t: return
        self.inspector_view.tag_remove("highlight", "1.0", "end")
        idx = self.inspector_view.search(t, "1.0", stopindex="end", nocase=True)
        if idx:
            end_idx = f"{idx}+{len(t)}c"; self.inspector_view.tag_add("highlight", idx, end_idx); self.inspector_view.see(idx)
            self.set_status(f"Found '{t}'")
        else: self.set_status(f"'{t}' not found.")

    def _analysis_job(self):
        self.set_ui_state("disabled"); self.set_status("Decompiling...")
        if self.engine_var.get() == "apktool": r = decompile_with_apktool(self.apk_path, self.output_dir)
        else: r = decompile_with_androguard(self.apk_path, self.output_dir)
        self.log(r["output"])
        if not r["success"]: self.log("Decompilation failed."); self.set_status("Failed"); self.set_ui_state("normal"); return
        self.log("Decompilation successful."); self.app.after(0, self.populate_tree, self.file_tree, self.output_dir)
        self.set_status("Analyzing..."); self.log("\n-> Analyzing...")
        results = scan_project(self.output_dir); self.log("[✔] Analysis complete.")
        self.report_text = self.format_report(results); self.app.after(0, self.display_report_in_tab)
        self.set_status("Analysis Complete"); self.set_ui_state("normal")

    def _inspect_job(self, path):
        meta = inspect_file_metadata(path); self.app.after(0, self.metadata_view.insert, "1.0", meta)
        for line in generate_hex_view(path): self.app.after(0, self.inspector_view.insert, "end", line)
        self.set_status("Inspection Complete")

    def display_report_in_tab(self):
        try: self.tab_view.delete("Static Analysis Report")
        except: pass
        self.tab_view.add("Static Analysis Report"); rf = self.tab_view.tab("Static Analysis Report")
        rf.grid_columnconfigure(0, weight=1); rf.grid_rowconfigure(0, weight=1)
        tb = ctk.CTkTextbox(rf, font=("monospace", 13)); tb.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        tb.insert("1.0", self.report_text); self.tab_view.set("Static Analysis Report")

    def format_report(self, results):
        report = [f"Scanned Files: {results.get('scanned_files', 0)}\n"]
        report.append("---[ API Keys ]---")
        keys = results.get('api_keys', [])
        if keys:
            for i in keys:
                report.extend([f"  [+] Key: {i['match']}", f"      File: {i['file']}\n"])
        else:
            report.append("  No hardcoded secrets found.\n")

        report.append("\n---[ URLs ]---")
        urls = results.get('urls', [])
        if urls:
            for i in urls:
                report.extend([f"  [+] URL: {i['url']}", f"      File: {i['file']}\n"])
        else:
            report.append("  No URLs found.\n")

        report.append("\n---[ Permissions ]---")
        permissions = results.get('permissions', [])
        if permissions:
            report.append("\n".join(f"  - {p}" for p in permissions))
        else:
            report.append("  No permissions found.\n")

        report.append("\n---[ Exported Activities ]---")
        exported_activities = results.get('exported_activities', [])
        if exported_activities:
            report.append("\n".join(f"  - {a}" for a in exported_activities))
        else:
            report.append("  No exported activities found.\n")

        report.append("\n---[ Deep Links ]---")
        deep_links = results.get('deep_links', [])
        if deep_links:
            report.append("\n".join(f"  - {dl}" for dl in deep_links))
        else:
            report.append("  No deep links found.\n")

        return "\n".join(report)


    def populate_tree(self, tree, path):
        for i in tree.get_children(): tree.delete(i)
        def insert(p, i_path):
            n=os.path.basename(i_path); node=tree.insert(p, "end", text=n, open=False, values=[i_path])
            if os.path.isdir(i_path):
                try: [insert(node, os.path.join(i_path, s)) for s in sorted(os.listdir(i_path))]
                except OSError: pass
        try: [insert("", os.path.join(path, r)) for r in sorted(os.listdir(path))]
        except: pass

    def log(self, msg): self.app.after(0, lambda: (self.log_box.insert("end", msg.strip() + "\n"), self.log_box.see("end")))
    def set_status(self, msg): self.app.after(0, self.status_label.configure, {"text": msg})
    
    def set_ui_state(self, state):
        d = state == "normal"
        self.app.after(0, self.select_apk_btn.configure, {"state": state})
        self.app.after(0, self.select_out_btn.configure, {"state": state})
        self.app.after(0, self.analyze_btn.configure, {"state": state})
        self.app.after(0, self.export_btn.configure, {"state": "normal" if d and self.report_text else "disabled"})

    def check_button_states(self):
        if self.apk_path and self.output_dir: self.analyze_btn.configure(state="normal")
        else: self.analyze_btn.configure(state="disabled")