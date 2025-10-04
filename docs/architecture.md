APK Ghost — Architecture (brief)

- apkghost/                     # Python package
  - main.py                     # CLI entrypoint
  - gui.py                      # GUI launcher
  - controller.py               # orchestrator between UI & backend
  - config.py                   # config & constants
  - logger.py                   # central logging
  - tools_integration.py        # wrappers for apktool/jadx/adb
  - analyzer/                   # static/dynamic analysis modules
  - report/                     # report generation
  - vt/                         # VirusTotal client (optional)
  - plugins/                    # plugin API
- tools/                        # optional local helper scripts
- resources/                    # icons & templates

Design notes:
- Long running tasks run in background threads; GUI updated via callbacks.
- All external tool invocations are captured and logged.
- Sensitive outputs (findings) are saved only to the project folder and can be encrypted later.
