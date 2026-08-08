# -*- mode: python ; coding: utf-8 -*-

import os
import sys

block_cipher = None

project_dir = os.path.abspath(os.path.join(SPECPATH, ".."))

a = Analysis(
    [os.path.join(project_dir, 'main.py')],
    pathex=[project_dir],
    binaries=[],
    datas=[
        (os.path.join(project_dir, 'samples'), 'samples'),
        (os.path.join(project_dir, 'web'), 'web'),
    ],
    hiddenimports=[
        'qt_compat',
        'PySide6',
        'PySide6.QtCore',
        'PySide6.QtGui',
        'PySide6.QtWidgets',
        'scipy.special.cython_special',
        'sklearn.utils._typedefs',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
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
    name='PhishGuardAI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
