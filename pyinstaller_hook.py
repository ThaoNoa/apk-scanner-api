# pyinstaller_hook.py
import os
import sys


def hook():
    """Hook để đảm bảo public.xml được copy vào exe"""
    print("PyInstaller hook: Ensuring public.xml is included...")

    # Tìm đường dẫn androguard
    try:
        import androguard
        androguard_path = os.path.dirname(androguard.__file__)
        resources_path = os.path.join(androguard_path, 'core', 'resources')
        public_xml = os.path.join(resources_path, 'public.xml')

        if os.path.exists(public_xml):
            print(f"Found public.xml at: {public_xml}")
        else:
            print(f"WARNING: public.xml not found at {public_xml}")
    except Exception as e:
        print(f"Error: {e}")


hook()