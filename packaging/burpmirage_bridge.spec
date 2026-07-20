# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for the standalone BurpMirage Frida bridge.

Produces a single self-contained ``burpmirage-bridge.exe`` that bundles:
  - the Python runtime
  - the ``frida`` package (native _frida extension)
  - ``frida_bridge.py`` (entry point)
  - ``hooks.js`` (added as data so the exe can run without --script)

Build:
    pip install pyinstaller frida
    pyinstaller packaging/burpmirage_bridge.spec --noconfirm

Output:
    dist/burpmirage-bridge.exe
"""

import os

block_cipher = None

ROOT = os.path.abspath(os.getcwd())
FRIDA_DIR = os.path.join(ROOT, "src", "main", "resources", "frida")

a = Analysis(
    [os.path.join(FRIDA_DIR, "frida_bridge.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[
        (os.path.join(FRIDA_DIR, "hooks.js"), "."),
    ],
    hiddenimports=["frida", "_frida"],
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "frida_tools"],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="burpmirage-bridge",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
