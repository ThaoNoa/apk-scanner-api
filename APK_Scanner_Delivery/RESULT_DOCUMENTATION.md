# APK Malware Scanner - Result Information Documentation

## Overview

This document explains each field in the JSON response returned by the APK Malware Scanner API.

## Response Structure

{
  "batch_id": "string",
  "total_files": 0,
  "total_duration": 0.0,
  "results": [],
  "summary": {}
}

## Field Descriptions

### Top-Level Fields

- batch_id: string - Unique identifier for this scan batch
- total_files: integer - Number of APK files processed
- total_duration: float - Total processing time in seconds
- results: array - Array of individual scan results
- summary: object - Aggregated statistics

### ScanResult Fields (per file)

- filename: string - Name of the scanned APK file
- scan_id: string - Unique identifier for this scan
- timestamp: string - ISO format timestamp of scan completion
- scan_duration: float - Time taken to scan this file (seconds)
- is_malicious: boolean - TRUE if malware detected, FALSE otherwise
- risk_level: string - SAFE, LOW, MEDIUM, HIGH, or CRITICAL
- risk_score: float - Numerical score from 0 (safe) to 100 (critical)
- confidence: float - Confidence level from 0 percent to 100 percent
- permissions: array - All permissions requested by the app
- dangerous_permissions: array - Subset of permissions that are high-risk
- voice_phishing_analysis: object - Voice phishing specific analysis

### VoicePhishingAnalysis Fields

- outgoing_hijacking_detected: boolean - Can app hijack outgoing calls?
- outgoing_hijacking_method: string - Method 1 (number modification) or Method 2 (redial)
- outgoing_hijacking_permissions: array - Permissions used for outgoing hijacking
- incoming_spoofing_detected: boolean - Can app spoof incoming caller ID?
- incoming_spoofing_method: string - Service-based or listener-based monitoring
- call_log_manipulation_detected: boolean - Can app read/write call logs?
- contacts_manipulation_detected: boolean - Can app read/write contacts?
- risk_score: integer - Voice phishing specific risk score (0 to 100)
- risk_level: string - SAFE, LOW, MEDIUM, HIGH, or CRITICAL

### Findings Fields

- type: string - Category of finding (e.g., dangerous_permission)
- severity: string - critical, high, medium, low, or info
- description: string - Human-readable explanation
- recommendation: string - Suggested action

### Summary Fields

- total_malicious: integer - Number of malicious files detected
- total_clean: integer - Number of clean files
- total_error: integer - Number of files that failed to scan
- by_risk_level: object - Count of files per risk level
- voice_phishing_detected: integer - Number of voice phishing apps found
- average_risk_score: float - Average risk score across all files
- average_scan_time: float - Average scan time per file in seconds

## Risk Level Interpretation

- SAFE (0-9): No suspicious indicators - No action required
- LOW (10-24): Minor concerns - Monitor
- MEDIUM (25-49): Suspicious patterns detected - Investigate
- HIGH (50-69): Strong indicators of malware - Block or Quarantine
- CRITICAL (70-100): Confirmed malware - Immediate action required

## Example Response

{
  "filename": "suspicious_app.apk",
  "is_malicious": true,
  "risk_level": "HIGH",
  "risk_score": 72.5,
  "voice_phishing_analysis": {
    "outgoing_hijacking_detected": true,
    "outgoing_hijacking_method": "Method 1: Number modification",
    "outgoing_hijacking_permissions": [
      "android.permission.PROCESS_OUTGOING_CALLS",
      "android.permission.READ_PHONE_STATE"
    ]
  },
  "findings": [
    {
      "type": "outgoing_call_hijacking",
      "severity": "critical",
      "description": "App can hijack calls to financial institutions",
      "recommendation": "Block immediately"
    }
  ]
}