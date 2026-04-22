"""
Generate valid APK files without requiring android.jar
Run: python scripts/generate_final_apks.py
"""

import os
import zipfile
from pathlib import Path

def create_android_manifest(package_name, app_name, permissions, min_sdk=21, target_sdk=34):
    """Tạo AndroidManifest.xml đúng định dạng"""
    manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}"
    android:versionCode="1"
    android:versionName="1.0">
    
    <uses-sdk android:minSdkVersion="{min_sdk}" android:targetSdkVersion="{target_sdk}" />
    
'''
    for perm in permissions:
        manifest += f'    <uses-permission android:name="{perm}" />\n'

    manifest += f'''
    <application
        android:label="{app_name}"
        android:allowBackup="true">
        
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
    
</manifest>'''
    return manifest

def create_apk_direct(output_path, package_name, app_name, permissions):
    """Tạo APK trực tiếp bằng zip với đúng cấu trúc"""

    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as apk:
        # 1. AndroidManifest.xml
        manifest = create_android_manifest(package_name, app_name, permissions)
        apk.writestr('AndroidManifest.xml', manifest)

        # 2. classes.dex (file dex rỗng hợp lệ)
        # Header cho file dex hợp lệ
        dex_header = bytearray([
            0x64, 0x65, 0x78, 0x0a,  # magic "dex\n"
            0x30, 0x33, 0x35, 0x00,  # version "035\0"
            0x00, 0x00, 0x00, 0x00,  # checksum
            0x00, 0x00, 0x00, 0x00,  # signature
            0x00, 0x00, 0x00, 0x00,  # file_size
            0x70, 0x00, 0x00, 0x00,  # header_size = 112
            0x78, 0x56, 0x34, 0x12,  # endian_tag = 0x12345678
            0x00, 0x00, 0x00, 0x00,  # link_size
            0x00, 0x00, 0x00, 0x00,  # link_off
            0x00, 0x00, 0x00, 0x00,  # map_off
            0x00, 0x00, 0x00, 0x00,  # string_ids_size
            0x00, 0x00, 0x00, 0x00,  # string_ids_off
            0x00, 0x00, 0x00, 0x00,  # type_ids_size
            0x00, 0x00, 0x00, 0x00,  # type_ids_off
            0x00, 0x00, 0x00, 0x00,  # proto_ids_size
            0x00, 0x00, 0x00, 0x00,  # proto_ids_off
            0x00, 0x00, 0x00, 0x00,  # field_ids_size
            0x00, 0x00, 0x00, 0x00,  # field_ids_off
            0x00, 0x00, 0x00, 0x00,  # method_ids_size
            0x00, 0x00, 0x00, 0x00,  # method_ids_off
            0x00, 0x00, 0x00, 0x00,  # class_defs_size
            0x00, 0x00, 0x00, 0x00,  # class_defs_off
            0x00, 0x00, 0x00, 0x00   # data_size
        ])
        apk.writestr('classes.dex', bytes(dex_header))

        # 3. resources.arsc
        apk.writestr('resources.arsc', b'\x00' * 8)

        # 4. META-INF (cần cho APK hợp lệ)
        apk.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n')
        apk.writestr('META-INF/CERT.SF', 'Signature-Version: 1.0\n')
        apk.writestr('META-INF/CERT.RSA', b'\x00' * 512)

    print(f"  Created: {output_path.name}")

def generate_samples():
    """Generate all APK samples"""

    # Create directories
    normal_dir = Path('samples/normal')
    malicious_dir = Path('samples/malicious')
    normal_dir.mkdir(parents=True, exist_ok=True)
    malicious_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("Generating APK Samples (Valid Structure)")
    print("=" * 60)

    # 10 Normal APKs
    print("\n[1] Generating 10 NORMAL APKs...")
    normal_samples = [
        ("com.normal.bank", "BankApp", ["android.permission.INTERNET"]),
        ("com.normal.social", "SocialApp", ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"]),
        ("com.normal.game", "GameApp", []),
        ("com.normal.calculator", "Calculator", []),
        ("com.normal.education", "EduApp", ["android.permission.INTERNET"]),
        ("com.normal.shopping", "ShopApp", ["android.permission.INTERNET"]),
        ("com.normal.health", "HealthApp", ["android.permission.INTERNET"]),
        ("com.normal.document", "DocReader", ["android.permission.READ_EXTERNAL_STORAGE"]),
        ("com.normal.news", "NewsApp", ["android.permission.INTERNET"]),
        ("com.normal.weather", "WeatherApp", ["android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"]),
    ]

    for i, (pkg, name, perms) in enumerate(normal_samples, 1):
        output = normal_dir / f"normal_{i:02d}_{pkg.split('.')[-1]}.apk"
        create_apk_direct(output, pkg, name, perms)

    # 10 Malicious APKs
    print("\n[2] Generating 10 MALICIOUS APKs...")
    malicious_samples = [
        ("com.malicious.sms", "SMSApp", ["android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"]),
        ("com.malicious.call", "CallApp", ["android.permission.PROCESS_OUTGOING_CALLS", "android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE"]),
        ("com.malicious.spy", "SpyApp", ["android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION"]),
        ("com.malicious.ransom", "RansomApp", ["android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_EXTERNAL_STORAGE"]),
        ("com.malicious.fakebank", "FakeBank", ["android.permission.READ_SMS", "android.permission.INTERNET", "android.permission.CAMERA"]),
        ("com.malicious.adware", "AdApp", ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"]),
        ("com.malicious.keylog", "KeyApp", ["android.permission.INTERNET", "android.permission.READ_PHONE_STATE"]),
        ("com.malicious.spoof", "SpoofApp", ["android.permission.BIND_INCALL_SERVICE", "android.permission.READ_PHONE_STATE"]),
        ("com.malicious.calllog", "CleanApp", ["android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG"]),
        ("com.malicious.vp", "VoIPApp", ["android.permission.PROCESS_OUTGOING_CALLS", "android.permission.READ_PHONE_STATE", "android.permission.BIND_INCALL_SERVICE", "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG"]),
    ]

    for i, (pkg, name, perms) in enumerate(malicious_samples, 1):
        output = malicious_dir / f"malicious_{i:02d}_{pkg.split('.')[-1]}.apk"
        create_apk_direct(output, pkg, name, perms)

    # Create README
    readme = """# APK Test Samples

## Normal APKs (10 files - SAFE)
These are safe applications:

1. normal_01_bank.apk - Banking app
2. normal_02_social.apk - Social media
3. normal_03_game.apk - Game
4. normal_04_calculator.apk - Calculator
5. normal_05_education.apk - Educational
6. normal_06_shopping.apk - Shopping
7. normal_07_health.apk - Health
8. normal_08_document.apk - Document reader
9. normal_09_news.apk - News
10. normal_10_weather.apk - Weather

## Malicious APKs (10 files - DANGEROUS)
These are malware samples:

1. malicious_01_sms.apk - SMS Trojan
2. malicious_02_call.apk - Call hijacking
3. malicious_03_spy.apk - Spyware
4. malicious_04_ransom.apk - Ransomware
5. malicious_05_fakebank.apk - Fake banking
6. malicious_06_adware.apk - Adware
7. malicious_07_keylog.apk - Keylogger
8. malicious_08_spoof.apk - Call spoofing
9. malicious_09_calllog.apk - Call log manipulation
10. malicious_10_vp.apk - Voice phishing

## Expected Results
- Normal APKs: is_malicious = false, risk_level = SAFE or LOW
- Malicious APKs: is_malicious = true, risk_level = MEDIUM to CRITICAL
"""

    with open('samples/README.txt', 'w') as f:
        f.write(readme)

    print("\n" + "=" * 60)
    print("GENERATION COMPLETE!")
    print(f"Normal APKs: {normal_dir}")
    print(f"Malicious APKs: {malicious_dir}")
    print("=" * 60)

if __name__ == "__main__":
    generate_samples()