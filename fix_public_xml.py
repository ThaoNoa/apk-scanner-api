# fix_public_xml.py
import os
import sys


def fix_androguard_public_xml():
    """Tạo file public.xml trong thư mục androguard"""

    # Tìm đường dẫn androguard
    try:
        # Lấy đường dẫn site-packages
        import site
        site_packages = site.getsitepackages()

        androguard_path = None
        for sp in site_packages:
            test_path = os.path.join(sp, 'androguard')
            if os.path.exists(test_path):
                androguard_path = test_path
                break

        if not androguard_path:
            # Thử import androguard
            import androguard
            androguard_path = os.path.dirname(androguard.__file__)

        resources_path = os.path.join(androguard_path, 'core', 'resources')
        public_xml_path = os.path.join(resources_path, 'public.xml')

        print(f"Androguard path: {androguard_path}")
        print(f"Resources path: {resources_path}")
        print(f"Target file: {public_xml_path}")

        # Tạo thư mục nếu chưa có
        os.makedirs(resources_path, exist_ok=True)

        # Nội dung public.xml
        public_xml_content = '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <public type="attr" name="color" id="0x01010000" />
    <public type="attr" name="theme" id="0x01010001" />
    <public type="attr" name="background" id="0x01010002" />
    <public type="attr" name="textColor" id="0x01010003" />
    <public type="attr" name="layout_width" id="0x01010004" />
    <public type="attr" name="layout_height" id="0x01010005" />
    <public type="drawable" name="icon" id="0x01020000" />
    <public type="drawable" name="logo" id="0x01020001" />
    <public type="string" name="app_name" id="0x01030000" />
    <public type="string" name="hello_world" id="0x01030001" />
    <public type="style" name="Theme.AppCompat" id="0x01040000" />
    <public type="style" name="Theme.AppCompat.Light" id="0x01040001" />
    <public type="id" name="button1" id="0x01050000" />
    <public type="id" name="text1" id="0x01050001" />
    <public type="layout" name="activity_main" id="0x01060000" />
    <public type="layout" name="activity_settings" id="0x01060001" />
</resources>'''

        # Ghi file
        with open(public_xml_path, 'w', encoding='utf-8') as f:
            f.write(public_xml_content)

        print(f"✅ SUCCESS: Created {public_xml_path}")
        return True

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("=" * 50)
    print("Fixing Androguard public.xml")
    print("=" * 50)

    if fix_androguard_public_xml():
        print("\n✅ Done! You can now build the exe again.")
    else:
        print("\n❌ Failed! Please run this script as Administrator.")

    input("\nPress Enter to exit...")