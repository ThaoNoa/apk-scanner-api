"""
Generate 10 normal and 10 malicious APK samples for testing
Run: python scripts/generate_apk_samples.py
"""

import os
import zipfile
from pathlib import Path


def create_apk_sample(output_path, package_name, app_name, permissions, is_malicious=False, malware_type=None):
    """Create a test APK file"""

    with zipfile.ZipFile(output_path, 'w') as apk:
        # Create AndroidManifest.xml
        manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}"
    android:versionCode="1"
    android:versionName="1.0">

    <application android:label="{app_name}">
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>

'''
        for perm in permissions:
            manifest += f'    <uses-permission android:name="{perm}" />\n'
        manifest += '</manifest>'

        apk.writestr('AndroidManifest.xml', manifest)
        apk.writestr('classes.dex', b'fake dex content')
        apk.writestr('resources.arsc', b'fake resources')

    print(f"  Created: {output_path.name}")


def main():
    # Create directories
    normal_dir = Path('samples/normal')
    malicious_dir = Path('samples/malicious')
    normal_dir.mkdir(parents=True, exist_ok=True)
    malicious_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("Generating APK Samples")
    print("=" * 60)

    # 10 Normal APKs
    print("\n[1] Generating 10 NORMAL APKs...")
    normal_samples = [
        ("com.bank.abc", "ABCBank", ["android.permission.INTERNET"]),
        ("com.social.app", "SocialApp", ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"]),
        ("com.game.puzzle", "PuzzleGame", []),
        ("com.calc.tool", "SmartCalc", []),
        ("com.edu.kids", "KidsLearn", ["android.permission.INTERNET"]),
        ("com.shop.easy", "EasyShop", ["android.permission.INTERNET"]),
        ("com.health.fit", "FitTrack", ["android.permission.INTERNET"]),
        ("com.office.docs", "DocReader", ["android.permission.READ_EXTERNAL_STORAGE"]),
        ("com.news.daily", "DailyNews", ["android.permission.INTERNET"]),
        ("com.weather.pro", "WeatherPro", ["android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"]),
    ]

    for i, (pkg, name, perms) in enumerate(normal_samples, 1):
        output = normal_dir / f"normal_{i:02d}_{name}.apk"
        create_apk_sample(output, pkg, name, perms, is_malicious=False)

    # 10 Malicious APKs (different malware types)
    print("\n[2] Generating 10 MALICIOUS APKs (different types)...")
    malicious_samples = [
        # Type 1: SMS Trojan
        ("com.sms.trojan", "SMSApp",
         ["android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"],
         "sms_trojan"),
        # Type 2: Call Hijacking
        ("com.call.hijack", "CallManager",
         ["android.permission.PROCESS_OUTGOING_CALLS", "android.permission.READ_PHONE_STATE",
          "android.permission.CALL_PHONE"], "call_hijacking"),
        # Type 3: Spyware
        ("com.spy.agent", "SystemService",
         ["android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION"],
         "spyware"),
        # Type 4: Ransomware
        ("com.ransom.crypto", "CryptoWallet",
         ["android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_EXTERNAL_STORAGE"], "ransomware"),
        # Type 5: Fake Banking
        ("com.fake.bank", "SecureBank",
         ["android.permission.READ_SMS", "android.permission.INTERNET", "android.permission.CAMERA"], "fake_banking"),
        # Type 6: Adware
        ("com.ad.free", "FreeGames", ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"],
         "adware"),
        # Type 7: Keylogger
        ("com.key.log", "KeyboardPlus", ["android.permission.INTERNET", "android.permission.READ_PHONE_STATE"],
         "keylogger"),
        # Type 8: Incoming Spoofing
        ("com.spoof.call", "CallBlocker",
         ["android.permission.BIND_INCALL_SERVICE", "android.permission.READ_PHONE_STATE"], "incoming_spoofing"),
        # Type 9: Call Log Manipulation
        ("com.log.hide", "SystemCleaner", ["android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG"],
         "call_log_manipulation"),
        # Type 10: Full Voice Phishing
        ("com.vp.hijack", "VoIPCaller",
         ["android.permission.PROCESS_OUTGOING_CALLS", "android.permission.READ_PHONE_STATE",
          "android.permission.BIND_INCALL_SERVICE", "android.permission.READ_CALL_LOG",
          "android.permission.WRITE_CALL_LOG"], "voice_phishing"),
    ]

    for i, (pkg, name, perms, mtype) in enumerate(malicious_samples, 1):
        output = malicious_dir / f"malicious_{i:02d}_{mtype}.apk"
        create_apk_sample(output, pkg, name, perms, is_malicious=True, malware_type=mtype)

    # Create README
    readme = """# APK Test Samples

## Normal APKs (10 files)
These are safe applications:
1. normal_01_ABCBank.apk - Banking app
2. normal_02_SocialApp.apk - Social media
3. normal_03_PuzzleGame.apk - Mobile game
4. normal_04_SmartCalc.apk - Calculator
5. normal_05_KidsLearn.apk - Educational
6. normal_06_EasyShop.apk - Shopping
7. normal_07_FitTrack.apk - Health tracking
8. normal_08_DocReader.apk - Document reader
9. normal_09_DailyNews.apk - News reader
10. normal_10_WeatherPro.apk - Weather app

## Malicious APKs (10 files - different malware types)
1. malicious_01_sms_trojan.apk - SMS Trojan (reads/sends SMS)
2. malicious_02_call_hijacking.apk - Outgoing call hijacking
3. malicious_03_spyware.apk - Spyware (camera, location, audio)
4. malicious_04_ransomware.apk - Ransomware
5. malicious_05_fake_banking.apk - Fake banking app
6. malicious_06_adware.apk - Adware
7. malicious_07_keylogger.apk - Keylogger
8. malicious_08_incoming_spoofing.apk - Incoming call spoofing
9. malicious_09_call_log_manipulation.apk - Call log manipulation
10. malicious_10_voice_phishing.apk - Full voice phishing (all permissions)
"""

    with open('samples/README.txt', 'w') as f:
        f.write(readme)

    print("\n" + "=" * 60)
    print("GENERATION COMPLETE!")
    print(f"Normal APKs: {normal_dir}")
    print(f"Malicious APKs: {malicious_dir}")
    print("=" * 60)


if __name__ == "__main__":
    main()