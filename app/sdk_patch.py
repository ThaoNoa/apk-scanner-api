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

    # Đường dẫn đến platform android-36.1
    platform_dir = os.path.join(REAL_SDK_PATH, 'platforms', 'android-36.1', 'data', 'res', 'values')
    os.makedirs(platform_dir, exist_ok=True)

    # Tạo file public.xml
    public_xml_path = os.path.join(platform_dir, 'public.xml')

    public_xml_content = '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <public type="attr" name="color" id="0x01010000" />
    <public type="drawable" name="icon" id="0x01010001" />
    <public type="string" name="app_name" id="0x01010002" />
    <public type="layout" name="main" id="0x01010003" />
    <public type="id" name="button1" id="0x01010004" />
</resources>'''

    if not os.path.exists(public_xml_path):
        with open(public_xml_path, 'w', encoding='utf-8') as f:
            f.write(public_xml_content)
        print(f"Created: {public_xml_path}")

    # Cũng tạo cho các version phổ biến khác (để phòng trường hợp)
    common_versions = ['android-30', 'android-31', 'android-32', 'android-33', 'android-34', 'android-35', 'android-36']

    for version in common_versions:
        version_dir = os.path.join(REAL_SDK_PATH, 'platforms', version, 'data', 'res', 'values')
        os.makedirs(version_dir, exist_ok=True)

        xml_path = os.path.join(version_dir, 'public.xml')
        if not os.path.exists(xml_path):
            with open(xml_path, 'w', encoding='utf-8') as f:
                f.write(public_xml_content)

    print(f"Android SDK ready at: {REAL_SDK_PATH}")
    return REAL_SDK_PATH


# Chạy ngay khi import
setup_android_sdk()