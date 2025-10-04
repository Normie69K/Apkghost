import argparse, os
from .tools_integration import run_apktool_decompile, run_apktool_build, run_jadx
from .analyzer.static_analyzer import scan_strings_in_path
from .report.generator import save_json_report, save_html_report
from .logger import logger

def main():
    parser = argparse.ArgumentParser(prog="apkghost")
    parser.add_argument("--decompile", help="APK path to decompile")
    parser.add_argument("--analyze", help="Path to decompiled project to analyze")
    parser.add_argument("--gui", action="store_true", help="Launch GUI (if implemented)")
    args = parser.parse_args()

    if args.decompile:
        apk = args.decompile
        out = os.path.join(os.getcwd(), "decompiled_" + os.path.splitext(os.path.basename(apk))[0])
        code, text = run_apktool_decompile(apk, out)
        print(text)
        print("Return:", code)
    elif args.analyze:
        proj = args.analyze
        res = scan_strings_in_path(proj)
        rpt = save_json_report(res, os.path.join(proj, "analysis_report.json"))
        save_html_report(res, os.path.join(proj, "analysis_report.html"))
        print("Reports:", rpt)
    elif args.gui:
        try:
            from .gui import launch_gui
            launch_gui()
        except Exception as e:
            logger.exception("Failed to launch GUI: %s", e)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
