"""Build the desktop app for the current OS with PyInstaller (output in dist/).

    pip install -r requirements.txt pyinstaller
    python build.py
"""
import os

import PyInstaller.__main__

PyInstaller.__main__.run([
    "--noconfirm",
    "--onefile",
    "--windowed",
    "--name", "EmailLeakScanner",
    f"--add-data=web{os.pathsep}web",  # the separator is ';' on Windows, ':' elsewhere
    "gui.py",
])
