# -*- mode: python ; coding: utf-8 -*-

import sys
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Collect all necessary data files
a = Analysis(
    ['windows_service.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('app', 'app'),
        ('requirements.txt', '.'),
    ],
    hiddenimports=[
        'app.main',
        'app.models.scan_models',
        'app.scanners.androguard_scanner',
        'app.scanners.mobsf_scanner',
        'app.scanners.combined_scanner',
        'app.scanners.voice_phishing_scanner',
        'app.utils.file_handler',
        'app.utils.metrics_calculator',
        'app.utils.ground_truth',
        'uvicorn',
        'uvicorn.lifespan.on',
        'uvicorn.lifespan.off',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.http.h11_impl',
        'uvicorn.protocols.http.httptools_impl',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.protocols.websockets.wsproto_impl',
        'uvicorn.protocols.websockets.websockets_impl',
        'androguard',
        'androguard.core',
        'androguard.core.bytecodes',
        'androguard.core.analysis',
        'yara',
        'fastapi',
        'pydantic',
        'aiofiles',
        'requests',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='APKMalwareScanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='app_icon.ico'
)