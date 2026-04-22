======================================================================
APK MALWARE SCANNER - INSTALLATION AND USER GUIDE
======================================================================

CONTENTS:
1. Installation
2. Running as Windows Service
3. Using the API
4. Understanding Results
5. Troubleshooting

======================================================================
1. INSTALLATION
======================================================================

Option A - Portable (No installation):
- Double-click APKMalwareScanner.exe
- Keep the command prompt window open
- Open browser to http://localhost:8000/docs

Option B - Windows Service (Runs 24/7):
- Open Command Prompt as Administrator
- Run: APKMalwareScanner.exe service --install
- Start service: net start APKMalwareScanner
- Service will auto-start with Windows

======================================================================
2. USING THE API
======================================================================

Endpoint: POST http://localhost:8000/scan/apks
Parameters:
  - files: APK file(s) to scan
  - scan_androguard: true (recommended)

Example using curl:
  curl -X POST "http://localhost:8000/scan/apks" -F "files=@app.apk"

======================================================================
3. UNDERSTANDING RESULTS
======================================================================

Key Fields:
  - is_malicious: TRUE = malware detected
  - risk_level: SAFE/LOW/MEDIUM/HIGH/CRITICAL
  - risk_score: 0-100 (higher = more dangerous)
  - voice_phishing_analysis: Call hijacking detection

Risk Level Actions:
  - SAFE (0-9): No action needed
  - LOW (10-24): Monitor
  - MEDIUM (25-49): Investigate
  - HIGH (50-69): Block
  - CRITICAL (70-100): Immediate action

======================================================================
4. TROUBLESHOOTING
======================================================================

Issue: Port 8000 already in use
Solution: netstat -ano | findstr :8000 then taskkill /PID [PID] /F

Issue: Service won't start
Solution: Check logs at C:\ProgramData\APKMalwareScanner\scanner.log

Issue: Windows Firewall blocking
Solution: Allow port 8000 in Windows Firewall

======================================================================
For support: [Your Email]
======================================================================