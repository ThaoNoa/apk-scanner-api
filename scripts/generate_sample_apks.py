"""
Script to generate sample APK files for testing
Run: python scripts/generate_sample_apks.py
"""

import os
import zipfile
import json
from pathlib import Path


def create_fake_apk(output_path, package_name, app_name, is_malicious=False, malware_type=None):
    """Create a fake APK file (ZIP format) for testing"""

    with zipfile.ZipFile(output_path, 'w') as apk:
        # Create AndroidManifest.xml
        permissions = [
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE'
        ]

        if is_malicious:
            if malware_type == 'call_hijacking':
                permissions.extend([
                    'android.permission.PROCESS_OUTGOING_CALLS',
                    'android.permission.READ_PHONE_STATE',
                    'android.permission.CALL_PHONE'
                ])
            elif malware_type == 'spyware':
                permissions.extend([
                    'android.permission.CAMERA',
                    'android.permission.RECORD_AUDIO',
                    'android.permission.ACCESS_FINE_LOCATION'
                ])
            elif malware_type == 'sms_trojan':
                permissions.extend([
                    'android.permission.READ_SMS',
                    'android.permission.SEND_SMS',
                    'android.permission.RECEIVE_SMS'
                ])
            elif malware_type == 'ransomware':
                permissions.extend([
                    'android.permission.WRITE_EXTERNAL_STORAGE',
                    'android.permission.READ_EXTERNAL_STORAGE'
                ])

        manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}">

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

        # Create classes.dex (fake)
        apk.writestr('classes.dex', b'fake dex content for testing')

        # Create resources.arsc
        apk.writestr('resources.arsc', b'fake resources')

        # Create META-INF
        apk.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n')
        apk.writestr('META-INF/CERT.SF', 'Signature-Version: 1.0\n')
        apk.writestr('META-INF/CERT.RSA', b'fake certificate')


def generate_samples():
    """Generate all sample APKs"""

    # Create output directories
    normal_dir = Path('samples/normal')
    malicious_dir = Path('samples/malicious')
    normal_dir.mkdir(parents=True, exist_ok=True)
    malicious_dir.mkdir(parents=True, exist_ok=True)

    # Normal APKs
    normal_apps = [
        ('com.bank.abc', 'ABC Bank', 'normal_banking.apk'),
        ('com.social.facebook', 'SocialApp', 'normal_social.apk'),
        ('com.game.candy', 'Candy Game', 'normal_game.apk'),
        ('com.utility.calculator', 'Smart Calc', 'normal_utility.apk'),
        ('com.education.kids', 'Kids Learning', 'normal_education.apk'),
        ('com.shop.amazon', 'ShopEasy', 'normal_shopping.apk'),
        ('com.health.fit', 'FitTrack', 'normal_health.apk'),
        ('com.office.docs', 'DocViewer', 'normal_productivity.apk'),
        ('com.news.bbc', 'NewsDaily', 'normal_news.apk'),
        ('com.weather.accu', 'Weather Pro', 'normal_weather.apk'),
    ]

    print("Generating normal APKs...")
    for package, name, filename in normal_apps:
        output_path = normal_dir / filename
        create_fake_apk(output_path, package, name, is_malicious=False)
        print(f"  Created: {filename}")

    # Malicious APKs
    malicious_apps = [
        ('com.joker.malware', 'JokerMalware', 'malware_joker.apk', 'sms_trojan'),
        ('com.fakebank.secure', 'SecureBank', 'malware_fakebank.apk', 'call_hijacking'),
        ('com.call.hijack', 'CallManager', 'malware_call_hijack.apk', 'call_hijacking'),
        ('com.spy.agent', 'SystemService', 'malware_spy.apk', 'spyware'),
        ('com.ransom.crypto', 'CryptoWallet', 'malware_ransomware.apk', 'ransomware'),
        ('com.ad.free', 'FreeGames', 'malware_adware.apk', 'spyware'),
        ('com.sms.forward', 'MessageCenter', 'malware_sms_trojan.apk', 'sms_trojan'),
        ('com.key.log', 'KeyboardPlus', 'malware_keylogger.apk', 'spyware'),
        ('com.fake.installer', 'AppInstaller', 'malware_fake_app.apk', 'sms_trojan'),
        ('com.voice.phish', 'VoIPCaller', 'malware_voice_phishing.apk', 'call_hijacking'),
    ]

    print("\nGenerating malicious APKs...")
    for package, name, filename, mal_type in malicious_apps:
        output_path = malicious_dir / filename
        create_fake_apk(output_path, package, name, is_malicious=True, malware_type=mal_type)
        print(f"  Created: {filename}")

    # Create README
    readme_content = """# APK Sample Files for Testing

## Normal APKs (10 files)
These are safe applications with normal permissions:

1. normal_banking.apk - Banking app with internet permission
2. normal_social.apk - Social media app
3. normal_game.apk - Mobile game
4. normal_utility.apk - Calculator utility
5. normal_education.apk - Educational app
6. normal_shopping.apk - E-commerce app
7. normal_health.apk - Health tracking app
8. normal_productivity.apk - Document viewer
9. normal_news.apk - News reader
10. normal_weather.apk - Weather app

## Malicious APKs (10 files)
These are malware samples for testing detection:

1. malware_joker.apk - Joker malware (SMS fraud)
2. malware_fakebank.apk - Fake banking app (call hijacking)
3. malware_call_hijack.apk - Outgoing call hijacking
4. malware_spy.apk - Spyware (camera, location)
5. malware_ransomware.apk - Ransomware
6. malware_adware.apk - Adware
7. malware_sms_trojan.apk - SMS trojan
8. malware_keylogger.apk - Keylogger
9. malware_fake_app.apk - Fake app installer
10. malware_voice_phishing.apk - Voice phishing malware

## How to Use
1. Copy these APK files to your test device or emulator
2. Use the scanner API to analyze them
3. Compare results with expected classifications

Note: These are FAKE APK files created for testing purposes only.
"""

    with open('samples/README.txt', 'w') as f:
        f.write(readme_content)

    print("\n" + "=" * 50)
    print("SAMPLE GENERATION COMPLETE!")
    print(f"Normal APKs: {normal_dir}")
    print(f"Malicious APKs: {malicious_dir}")
    print("=" * 50)


if __name__ == "__main__":
    generate_samples()