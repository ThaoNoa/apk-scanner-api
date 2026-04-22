# apk_scanner.spec
# -*- mode: python ; coding: utf-8 -*-

import os
import sys

# Đường dẫn đến site-packages
site_packages = r"C:\Users\ACER\PycharmProjects\apk-scanner-api\.venv\Lib\site-packages"

# Hàm thu thập tất cả files trong thư mục
def collect_files(src_dir, dest_dir):
    datas = []
    if os.path.exists(src_dir):
        for root, dirs, files in os.walk(src_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, site_packages)
                datas.append((full_path, rel_path))
    return datas

# Thu thập tất cả các thư mục cần thiết của androguard
androguard_datas = []
androguard_datas.extend(collect_files(
    os.path.join(site_packages, 'androguard', 'core', 'api_specific_resources'),
    'androguard\\core\\api_specific_resources'
))
androguard_datas.extend(collect_files(
    os.path.join(site_packages, 'androguard', 'core', 'resources'),
    'androguard\\core\\resources'
))

# Thêm templates và config
datas = [
    ('app\\templates', 'app\\templates'),
    ('config.json', '.'),
] + androguard_datas

a = Analysis(
    ['windows_service.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[
        'app.main',
        'app.models.scan_models',
        'app.scanners.androguard_scanner',
        'app.scanners.combined_scanner',
        'app.scanners.voice_phishing_scanner',
        'app.utils.file_handler',
        'uvicorn',
        'jinja2',
        'androguard',
        'androguard.core',
        'androguard.core.bytecodes',
        'androguard.core.analysis',
        'androguard.core.api_specific_resources',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='APKMalwareScanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)