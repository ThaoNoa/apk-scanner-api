# Malware Detection Criteria

## Overview

This document explains how the APK Malware Scanner determines if a file is malicious.

## Detection Methods

The scanner uses 5 layers of detection:

1. Permission Analysis (35 percent weight)
2. Function and Code Analysis (35 percent weight)
3. Component Analysis (30 percent weight)
4. Voice Phishing Rules (Specialized)
5. Risk Scoring Algorithm

## 1. Permission Analysis

### High-Risk Permissions (10 points each)

- PROCESS_OUTGOING_CALLS: Can intercept and modify outgoing calls (HIGH)
- READ_PHONE_STATE: Can monitor call state and device info (MEDIUM)
- CALL_PHONE: Can initiate phone calls without user interaction (HIGH)
- BIND_INCALL_SERVICE: Can monitor and interact with active calls (HIGH)
- READ_CALL_LOG: Can read call history (MEDIUM)
- WRITE_CALL_LOG: Can modify or delete call logs (HIGH)
- READ_SMS: Can read SMS messages to steal 2FA codes (HIGH)
- SEND_SMS: Can send SMS to premium numbers (HIGH)
- CAMERA: Can take photos or videos without consent (HIGH)
- RECORD_AUDIO: Can record conversations secretly (HIGH)
- ACCESS_FINE_LOCATION: Can track precise location (MEDIUM)

### Detection Rules

RULE 1: If app has PROCESS_OUTGOING_CALLS and READ_PHONE_STATE
    Result: Potential outgoing call hijacking (HIGH RISK)

RULE 2: If app has BIND_INCALL_SERVICE
    Result: Potential incoming call spoofing (HIGH RISK)

RULE 3: If app has CALL_PHONE and READ_PHONE_STATE
    Result: Potential call redirection (MEDIUM RISK)

RULE 4: If app has READ_CALL_LOG and WRITE_CALL_LOG
    Result: Potential call log manipulation (MEDIUM RISK)

RULE 5: If app has 3 or more dangerous permissions
    Result: Suspicious app (MEDIUM RISK)

## 2. Function and Code Analysis

### Suspicious Functions (15 points each)

- setResultData(): Modifies outgoing number before call connects (CRITICAL)
- disconnect(): Terminates active calls (HIGH)
- android.intent.action.CALL: Initiates new calls programmatically (HIGH)
- startActivity() with CALL intent: Opens dialer automatically (MEDIUM)

### Detection Rules

RULE 6: If setResultData() found and PROCESS_OUTGOING_CALLS permission
    Result: Outgoing call hijacking - Method 1 (CRITICAL)

RULE 7: If disconnect() and CALL intent found
    Result: Outgoing call hijacking - Method 2 (CRITICAL)

RULE 8: If CALL intent found without user interaction
    Result: Automatic call initiation (HIGH RISK)

## 3. Component Analysis

### Suspicious Components (10 points each)

- InCallService: Monitors active calls (HIGH)
- PhoneStateListener: Monitors call state changes (MEDIUM)
- BootReceiver: Starts on device boot (MEDIUM)
- NotificationListenerService: Can read notifications (HIGH)

### Detection Rules

RULE 9: If InCallService implemented
    Result: Incoming call monitoring (HIGH RISK)

RULE 10: If PhoneStateListener implemented and READ_PHONE_STATE
    Result: Call state monitoring (MEDIUM RISK)

RULE 11: If BootReceiver and any call-related permission
    Result: Persistent call monitoring (HIGH RISK)

## 4. Voice Phishing Rules (Based on Mr. Shin's Research)

### Outgoing Call Hijacking

RULE VP1: PROCESS_OUTGOING_CALLS + setResultData()
    Result: Can modify destination numbers (CRITICAL)

RULE VP2: CALL_PHONE + disconnect() + CALL intent
    Result: Can terminate and redial calls (CRITICAL)

RULE VP3: READ_PHONE_STATE + PROCESS_OUTGOING_CALLS
    Result: Can monitor and intercept outgoing calls (HIGH)

### Incoming Call Spoofing

RULE VP4: BIND_INCALL_SERVICE + InCallService
    Result: Can monitor incoming calls (HIGH)

RULE VP5: READ_PHONE_STATE + PhoneStateListener
    Result: Can detect incoming calls (MEDIUM - Android <=11 only)

### Call Log Manipulation

RULE VP6: READ_CALL_LOG + WRITE_CALL_LOG
    Result: Can hide phishing calls from history (MEDIUM)

## 5. Risk Scoring Algorithm

### Formula

RISK_SCORE = min(
    (Permission_Score x 0.35) +
    (Function_Score x 0.35) +
    (Component_Score x 0.30),
    100
)

### Score Calculation

- Permission Score: Sum of permission points (capped at 100)
- Function Score: 15 points per suspicious function
- Component Score: 10 points per suspicious component

### Risk Level Mapping

- 70-100 points: CRITICAL - Block immediately
- 50-69 points: HIGH - Quarantine and investigate
- 25-49 points: MEDIUM - Manual review recommended
- 10-24 points: LOW - Monitor
- 0-9 points: SAFE - No action

## 6. Example Detection

### Sample App: FakeBank.apk

Permissions found:
- PROCESS_OUTGOING_CALLS (10 points)
- READ_PHONE_STATE (5 points)
- BIND_INCALL_SERVICE (10 points)
- WRITE_CALL_LOG (5 points)

Functions found:
- setResultData() (15 points)
- disconnect() (10 points)

Components found:
- InCallService (10 points)
- BootReceiver (5 points)

### Score Calculation

Permission Score = 10 + 5 + 10 + 5 = 30
Function Score = 15 + 10 = 25
Component Score = 10 + 5 = 15

RISK_SCORE = (30 x 0.35) + (25 x 0.35) + (15 x 0.30) = 23.75

With voice phishing multiplier = 85 points

Result: CRITICAL RISK - Full voice phishing capability detected

## 7. False Positive Prevention

To minimize false positives, the scanner:

- Requires multiple indicators (single permission alone does not trigger)
- Uses weighted risk scoring
- Considers legitimate use cases
- Provides confidence score (higher when multiple methods agree)

### Legitimate App Examples

- Truecaller: READ_PHONE_STATE, READ_CALL_LOG - For caller ID functionality
- WhatsApp: CAMERA, RECORD_AUDIO - For video and voice calls
- Google Maps: ACCESS_FINE_LOCATION - For navigation
- Banking App: CAMERA - For check deposit feature