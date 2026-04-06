# app/patch_androguard.py
import os
import sys


def patch_androguard_before_import():
    """Patch androguard để tránh lỗi public.xml - phải chạy TRƯỚC khi import androguard"""

    # Tìm SDK thực tế
    sdk_paths = [
        r"C:\Users\ACER\AppData\Local\Android\Sdk",
        r"C:\Android\Sdk",
        os.environ.get('ANDROID_HOME', ''),
        os.environ.get('ANDROID_SDK_ROOT', ''),
    ]

    sdk_path = None
    for path in sdk_paths:
        if path and os.path.exists(path):
            sdk_path = path
            break

    # Nếu không tìm thấy SDK, tạo dummy
    if not sdk_path:
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(os.path.dirname(__file__))

        sdk_path = os.path.join(base_path, 'dummy_sdk')
        os.makedirs(sdk_path, exist_ok=True)

    # Set environment variables
    os.environ['ANDROID_HOME'] = sdk_path
    os.environ['ANDROID_SDK_ROOT'] = sdk_path

    # Tạo file public.xml cho tất cả các version cần thiết
    versions = ['30', '31', '32', '33', '34', '35', '36', '37']

    for version in versions:
        values_dir = os.path.join(sdk_path, 'platforms', f'android-{version}', 'data', 'res', 'values')
        os.makedirs(values_dir, exist_ok=True)

        public_xml = os.path.join(values_dir, 'public.xml')
        if not os.path.exists(public_xml):
            with open(public_xml, 'w') as f:
                f.write('<?xml version="1.0" encoding="utf-8"?>\n')
                f.write('<resources>\n')
                f.write('    <public type="attr" name="color" id="0x01010000" />\n')
                f.write('</resources>\n')

    # Patch androguard.core.resources nếu đã được import
    try:
        import androguard.core.resources
        androguard.core.resources.ANDROID_PUBLIC_XML = public_xml
    except:
        pass

    return sdk_path


# Chạy patch NGAY LẬP TỨC khi file này được import
patch_androguard_before_import()