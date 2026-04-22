from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse
from typing import List
import time
import uuid
from datetime import datetime
import logging
from pathlib import Path
import os
import sys

from app.models.scan_models import BatchScanResponse, ScanResult, VoicePhishingAnalysis
from app.scanners.combined_scanner import CombinedScanner
from app.utils.file_handler import FileHandler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="APK Malware Scanner API",
    description="Scan APK files for malware with voice phishing detection",
    version="2.0.0",
)

# Initialize components
file_handler = FileHandler(upload_dir=Path("uploads"))
scanner = CombinedScanner(use_mobsf=False)

# Store scan results
scan_results: dict[str, BatchScanResponse] = {}

# ============================================================
# UI ENDPOINT - Complete HTML UI
# ============================================================

UI_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Malware Scanner</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; color: #fff; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; padding: 30px; background: rgba(255,255,255,0.1); border-radius: 20px; margin-bottom: 30px; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .status-badge { display: inline-block; padding: 5px 15px; background: #00ff88; color: #1a1a2e; border-radius: 20px; font-size: 0.8em; margin-top: 10px; }

        .scanner-options { background: rgba(255,255,255,0.1); border-radius: 15px; padding: 20px; margin-bottom: 30px; }
        .option-group { display: flex; gap: 30px; flex-wrap: wrap; }
        .option { display: flex; align-items: center; gap: 10px; }
        .option input { width: 20px; height: 20px; cursor: pointer; }

        .upload-area { background: rgba(255,255,255,0.05); border: 2px dashed rgba(255,255,255,0.3); border-radius: 20px; padding: 40px; text-align: center; cursor: pointer; transition: all 0.3s ease; margin-bottom: 30px; }
        .upload-area:hover { border-color: #00ff88; background: rgba(0,255,136,0.1); }
        .upload-area.drag-over { border-color: #00ff88; background: rgba(0,255,136,0.2); }
        .file-list { margin-top: 20px; }
        .file-item { background: rgba(255,255,255,0.1); padding: 10px; margin: 5px 0; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }
        .remove-file { background: #ff4444; border: none; color: white; padding: 5px 10px; border-radius: 5px; cursor: pointer; }

        .scan-btn { background: linear-gradient(90deg, #00ff88, #00b4d8); color: #1a1a2e; border: none; padding: 15px 40px; font-size: 1.2em; font-weight: bold; border-radius: 50px; cursor: pointer; width: 100%; margin-bottom: 30px; }
        .scan-btn:disabled { opacity: 0.5; cursor: not-allowed; }

        .loading { text-align: center; padding: 40px; display: none; }
        .spinner { width: 50px; height: 50px; border: 4px solid rgba(255,255,255,0.3); border-top-color: #00ff88; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 20px; }
        @keyframes spin { to { transform: rotate(360deg); } }

        .results-section { display: none; margin-top: 30px; }
        .result-card { background: rgba(255,255,255,0.1); border-radius: 15px; padding: 20px; margin-bottom: 20px; }
        .result-card.critical { border-left: 5px solid #ff0000; }
        .result-card.high { border-left: 5px solid #ff6600; }
        .result-card.medium { border-left: 5px solid #ffcc00; }
        .result-card.low { border-left: 5px solid #00ff88; }
        .result-card.safe { border-left: 5px solid #00ff88; }

        .result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; }
        .filename { font-size: 1.2em; font-weight: bold; word-break: break-all; }
        .risk-badge { padding: 5px 15px; border-radius: 20px; font-weight: bold; }
        .risk-critical { background: #ff0000; color: white; }
        .risk-high { background: #ff6600; color: white; }
        .risk-medium { background: #ffcc00; color: #1a1a2e; }
        .risk-low { background: #00ff88; color: #1a1a2e; }
        .risk-safe { background: #00aa55; color: white; }
        .risk-score { font-size: 1.5em; font-weight: bold; }

        .detail-section { margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.2); }
        .permission-list { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
        .permission-badge { background: rgba(255,255,255,0.2); padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-family: monospace; }
        .permission-dangerous { background: #ff4444; color: white; }
        .finding-item { background: rgba(0,0,0,0.3); padding: 8px; margin: 5px 0; border-radius: 8px; }

        .summary { background: rgba(0,0,0,0.3); border-radius: 15px; padding: 20px; margin-top: 20px; }
        .summary-stats { display: flex; gap: 20px; flex-wrap: wrap; margin-top: 15px; }
        .stat { flex: 1; text-align: center; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 10px; }
        .stat-value { font-size: 2em; font-weight: bold; }

        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }
        th { background: rgba(0,0,0,0.3); }

        @media (max-width: 768px) { .container { padding: 10px; } .header h1 { font-size: 1.5em; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ APK Malware Scanner</h1>
            <p>Advanced Android Malware Detection with Voice Phishing Analysis</p>
            <div class="status-badge" id="statusBadge">● System Ready</div>
        </div>

        <div class="scanner-options">
            <h3>⚙️ Scanner Configuration</h3>
            <div class="option-group">
                <div class="option"><input type="checkbox" id="scanAndroguard" checked><label>🔍 Androguard Scanner (Static Analysis)</label></div>
                <div class="option"><input type="checkbox" id="scanMobsf"><label>🐳 MOBSF Scanner (Deep Analysis)</label></div>
            </div>
        </div>

        <div class="upload-area" id="uploadArea">
            <div class="upload-icon">📁</div>
            <h3>Drag & Drop APK Files Here</h3>
            <p>or click to select files</p>
            <input type="file" id="fileInput" multiple accept=".apk" style="display: none;">
            <div class="file-list" id="fileList"><p style="color: #aaa;">No files selected</p></div>
        </div>

        <button class="scan-btn" id="scanBtn">🚀 Start Scan</button>

        <div class="loading" id="loading">
            <div class="spinner"></div>
            <p>Scanning APK files... Please wait</p>
        </div>

        <div class="results-section" id="resultsSection">
            <h2>📊 Scan Results</h2>
            <div id="resultsContainer"></div>
        </div>
    </div>

    <script>
        let selectedFiles = [];
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const fileList = document.getElementById('fileList');
        const scanBtn = document.getElementById('scanBtn');
        const loading = document.getElementById('loading');
        const resultsSection = document.getElementById('resultsSection');
        const resultsContainer = document.getElementById('resultsContainer');

        uploadArea.onclick = () => fileInput.click();
        uploadArea.ondragover = (e) => { e.preventDefault(); uploadArea.classList.add('drag-over'); };
        uploadArea.ondragleave = () => { uploadArea.classList.remove('drag-over'); };
        uploadArea.ondrop = (e) => {
            e.preventDefault();
            uploadArea.classList.remove('drag-over');
            addFiles(Array.from(e.dataTransfer.files));
        };
        fileInput.onchange = (e) => addFiles(Array.from(e.target.files));

        function addFiles(files) {
            for (const file of files) {
                if (file.name.endsWith('.apk') && !selectedFiles.find(f => f.name === file.name)) {
                    selectedFiles.push(file);
                }
            }
            updateFileList();
        }

        function removeFile(index) {
            selectedFiles.splice(index, 1);
            updateFileList();
        }

        function updateFileList() {
            if (selectedFiles.length === 0) {
                fileList.innerHTML = '<p style="color: #aaa;">No files selected</p>';
                return;
            }
            fileList.innerHTML = selectedFiles.map((file, index) => `
                <div class="file-item">
                    <span>📱 ${file.name}</span>
                    <button class="remove-file" onclick="removeFile(${index})">Remove</button>
                </div>
            `).join('');
        }

        scanBtn.onclick = async () => {
            if (selectedFiles.length === 0) { alert('Please select APK files'); return; }

            loading.style.display = 'block';
            resultsSection.style.display = 'none';
            scanBtn.disabled = true;

            const formData = new FormData();
            selectedFiles.forEach(f => formData.append('files', f));
            formData.append('scan_androguard', document.getElementById('scanAndroguard').checked);
            formData.append('scan_mobsf', document.getElementById('scanMobsf').checked);

            try {
                const response = await fetch('/scan/apks', { method: 'POST', body: formData });
                const data = await response.json();
                displayResults(data);
            } catch (err) {
                alert('Scan failed: ' + err.message);
            } finally {
                loading.style.display = 'none';
                scanBtn.disabled = false;
            }
        };

        function getRiskClass(level) {
            const classes = { 'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low', 'SAFE': 'safe' };
            return classes[level] || 'safe';
        }

        function displayResults(data) {
            resultsContainer.innerHTML = '';

            for (const result of data.results) {
                const riskClass = getRiskClass(result.risk_level);
                const scannersUsed = [];
                if (result.scanners.androguard) scannersUsed.push('Androguard');
                if (result.scanners.mobsf) scannersUsed.push('MOBSF');

                let dangerousPermsHtml = '';
                if (result.dangerous_permissions.length > 0) {
                    dangerousPermsHtml = `<div class="detail-section">
                        <strong>⚠️ Dangerous Permissions (${result.dangerous_permissions.length}):</strong>
                        <div class="permission-list">${result.dangerous_permissions.map(p => `<span class="permission-badge permission-dangerous">${p.split('.').pop()}</span>`).join('')}</div>
                    </div>`;
                }

                let voicePhishingHtml = '';
                if (result.voice_phishing_analysis && result.voice_phishing_analysis.outgoing_hijacking_detected) {
                    voicePhishingHtml = `<div class="detail-section" style="background: rgba(255,0,0,0.2); padding: 10px; border-radius: 8px;">
                        <strong>📞 VOICE PHISHING DETECTED:</strong><br>
                        ${result.voice_phishing_analysis.outgoing_hijacking_detected ? '• Outgoing call hijacking detected<br>' : ''}
                        ${result.voice_phishing_analysis.outgoing_hijacking_method ? `• Method: ${result.voice_phishing_analysis.outgoing_hijacking_method}<br>` : ''}
                        ${result.voice_phishing_analysis.incoming_spoofing_detected ? '• Incoming call spoofing detected' : ''}
                    </div>`;
                }

                let findingsHtml = '';
                if (result.findings && result.findings.length > 0) {
                    findingsHtml = `<div class="detail-section">
                        <strong>🔍 Findings (${result.findings.length}):</strong>
                        ${result.findings.slice(0, 5).map(f => `<div class="finding-item">⚠️ ${f.description}</div>`).join('')}
                    </div>`;
                }

                resultsContainer.innerHTML += `
                    <div class="result-card ${riskClass}">
                        <div class="result-header">
                            <span class="filename">📱 ${result.filename}</span>
                            <div>
                                <span class="risk-badge risk-${riskClass}">${result.risk_level}</span>
                                <span class="risk-score">${result.risk_score}/100</span>
                            </div>
                        </div>
                        <div>🔍 Scanned with: ${scannersUsed.join(', ')} | ⏱️ ${result.scan_duration.toFixed(2)}s</div>
                        <div>📋 Package: ${result.androguard_results?.package_name || 'N/A'} | Version: ${result.androguard_results?.version_name || 'N/A'}</div>
                        ${dangerousPermsHtml}
                        ${voicePhishingHtml}
                        ${findingsHtml}
                        <div class="detail-section">
                            <strong>✅ Verdict:</strong> ${result.is_malicious ? '⚠️ MALICIOUS - Take action immediately' : '✅ SAFE - No threat detected'}
                            <span style="margin-left: 20px;">🎯 Confidence: ${result.confidence}%</span>
                        </div>
                    </div>
                `;
            }

            // Summary
            const summary = data.summary;
            resultsContainer.innerHTML += `
                <div class="summary">
                    <h3>📈 Summary Report</h3>
                    <div class="summary-stats">
                        <div class="stat"><div class="stat-value">${data.total_files}</div><div>Total Files</div></div>
                        <div class="stat"><div class="stat-value" style="color:#ff4444;">${summary.total_malicious}</div><div>Malicious</div></div>
                        <div class="stat"><div class="stat-value" style="color:#00ff88;">${summary.total_clean}</div><div>Clean</div></div>
                        <div class="stat"><div class="stat-value">${summary.voice_phishing_detected || 0}</div><div>Voice Phishing</div></div>
                        <div class="stat"><div class="stat-value">${summary.average_risk_score.toFixed(1)}</div><div>Avg Risk Score</div></div>
                    </div>
                    <table>
                        <tr><th>Risk Level</th><th>Count</th></tr>
                        ${Object.entries(summary.by_risk_level).map(([level, count]) => `<tr><td>${level}</td><td>${count}</td></tr>`).join('')}
                    </table>
                    <div style="margin-top: 15px;"><strong>Scanners Used:</strong> ${Object.entries(summary.scanners_used).filter(([k,v]) => v).map(([k]) => k).join(', ')}</div>
                    <div><strong>Total Duration:</strong> ${data.total_duration.toFixed(2)} seconds</div>
                </div>
            `;

            resultsSection.style.display = 'block';
            resultsSection.scrollIntoView({ behavior: 'smooth' });
        }

        async function checkHealth() {
            try {
                const response = await fetch('/health');
                if (response.ok) document.getElementById('statusBadge').innerHTML = '✅ System Ready';
            } catch(e) { document.getElementById('statusBadge').innerHTML = '⚠️ Server Error'; }
        }
        checkHealth();
        setInterval(checkHealth, 30000);
    </script>
</body>
</html>
'''


@app.get("/", response_class=HTMLResponse)
@app.get("/ui", response_class=HTMLResponse)
async def get_ui():
    return HTMLResponse(content=UI_HTML)


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat(),
            "scanners": {"androguard": True, "mobsf": False}}


@app.post("/scan/apks", response_model=BatchScanResponse)
async def scan_apks(
        background_tasks: BackgroundTasks,
        files: List[UploadFile] = File(...),
        scan_androguard: bool = True,
        scan_mobsf: bool = False
):
    batch_start_time = time.perf_counter()
    batch_id = uuid.uuid4().hex

    for file in files:
        if not file.filename.endswith('.apk'):
            raise HTTPException(400, f"{file.filename} is not an APK file")

    file_paths = []
    try:
        file_paths = await file_handler.save_multiple_files(files)
        scan_options = {"scan_mobsf": scan_mobsf, "scan_androguard": scan_androguard}
        scan_results_list = await scanner.scan_multiple_apks(file_paths, scan_options)

        results = []
        risk_counts = {"SAFE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        voice_phishing_count = 0

        for scan_result in scan_results_list:
            androguard = scan_result.get("androguard", {})
            voice_phishing_data = androguard.get("voice_phishing", {})

            voice_phishing_analysis = None
            if voice_phishing_data and not voice_phishing_data.get("error"):
                voice_phishing_analysis = VoicePhishingAnalysis(
                    outgoing_hijacking_detected=voice_phishing_data.get("outgoing_hijacking_detected", False),
                    outgoing_hijacking_method=voice_phishing_data.get("outgoing_hijacking_method"),
                    outgoing_hijacking_permissions=voice_phishing_data.get("outgoing_hijacking_permissions", []),
                    incoming_spoofing_detected=voice_phishing_data.get("incoming_spoofing_detected", False),
                    incoming_spoofing_method=voice_phishing_data.get("incoming_spoofing_method"),
                    call_log_manipulation_detected=voice_phishing_data.get("call_log_manipulation_detected", False),
                    risk_score=voice_phishing_data.get("risk_score", 0),
                    risk_level=voice_phishing_data.get("risk_level", "SAFE")
                )
                if voice_phishing_data.get("outgoing_hijacking_detected"):
                    voice_phishing_count += 1

            result = ScanResult(
                filename=scan_result["filename"],
                scan_id=uuid.uuid4().hex,
                timestamp=datetime.now(),
                scan_duration=scan_result.get("scan_duration", 0),
                is_malicious=scan_result["is_malicious"],
                risk_level=scan_result["risk_level"],
                risk_score=scan_result["risk_score"],
                confidence=scan_result.get("confidence", 0),
                scanners={"androguard": scan_androguard, "mobsf": scan_mobsf},
                permissions=androguard.get("permissions", []),
                dangerous_permissions=androguard.get("dangerous_permissions", []),
                activities=androguard.get("activities", []),
                services=androguard.get("services", []),
                receivers=androguard.get("receivers", []),
                providers=androguard.get("providers", []),
                certificates=androguard.get("certificates", {}),
                mobsf_results={},
                androguard_results=androguard,
                findings=androguard.get("findings", []),
                detection_methods=scan_result.get("detection_methods", []),
                warnings=scan_result.get("warnings", []),
                errors=scan_result.get("errors", []),
                voice_phishing_analysis=voice_phishing_analysis
            )
            risk_counts[result.risk_level] = risk_counts.get(result.risk_level, 0) + 1
            results.append(result)

        batch_duration = time.perf_counter() - batch_start_time
        response = BatchScanResponse(
            batch_id=batch_id,
            total_files=len(files),
            total_duration=batch_duration,
            results=results,
            summary={
                "total_malicious": sum(1 for r in results if r.is_malicious),
                "total_clean": sum(1 for r in results if not r.is_malicious),
                "total_error": 0,
                "by_risk_level": risk_counts,
                "voice_phishing_detected": voice_phishing_count,
                "average_risk_score": sum(r.risk_score for r in results) / len(results) if results else 0,
                "average_scan_time": batch_duration / len(results) if results else 0,
                "scanners_used": {"androguard": scan_androguard, "mobsf": scan_mobsf}
            }
        )

        scan_results[batch_id] = response
        background_tasks.add_task(file_handler.cleanup_multiple_files, file_paths)
        return response

    except Exception as e:
        if file_paths:
            await file_handler.cleanup_multiple_files(file_paths)
        raise HTTPException(500, str(e))


@app.get("/scan/result/{batch_id}")
async def get_scan_result(batch_id: str):
    if batch_id in scan_results:
        return scan_results[batch_id]
    raise HTTPException(404, "Batch ID not found")