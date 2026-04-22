# app/sdk_patch.py
import os
import sys


def setup_android_sdk():
    """Setup Android SDK path và tạo file public.xml cần thiết"""

    # Đường dẫn SDK thực tế của bạn
    REAL_SDK_PATH = r"C:\Users\ACER\AppData\Local\Android\Sdk"

    if not os.path.exists(REAL_SDK_PATH):
        print(f"Warning: SDK not found at {REAL_SDK_PATH}")
        # Tạo dummy SDK trong thư mục hiện tại
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(os.path.dirname(__file__))
        REAL_SDK_PATH = os.path.join(base_path, 'dummy_sdk')
        os.makedirs(REAL_SDK_PATH, exist_ok=True)

    # Set environment variables
    os.environ['ANDROID_HOME'] = REAL_SDK_PATH
    os.environ['ANDROID_SDK_ROOT'] = REAL_SDK_PATH

    # Tạo file public.xml cho tất cả các platform versions
    platforms_dir = os.path.join(REAL_SDK_PATH, 'platforms')
    if os.path.exists(platforms_dir):
        for platform in os.listdir(platforms_dir):
            if platform.startswith('android-'):
                values_dir = os.path.join(platforms_dir, platform, 'data', 'res', 'values')
                os.makedirs(values_dir, exist_ok=True)

                public_xml = os.path.join(values_dir, 'public.xml')
                if not os.path.exists(public_xml):
                    with open(public_xml, 'w') as f:
                        f.write('<?xml version="1.0" encoding="utf-8"?>\n')
                        f.write('<resources>\n')
                        f.write('    <public type="attr" name="color" id="0x01010000" />\n')
                        f.write('    <public type="drawable" name="icon" id="0x01010001" />\n')
                        f.write('    <public type="string" name="app_name" id="0x01010002" />\n')
                        f.write('</resources>\n')
                    print(f"Created: {public_xml}")

    print(f"Android SDK ready at: {REAL_SDK_PATH}")
    return REAL_SDK_PATH


# Chạy ngay khi import
setup_android_sdk()