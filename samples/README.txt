# APK Test Samples

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
