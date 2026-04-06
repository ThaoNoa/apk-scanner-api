import requests
import json

# Giả lập ground truth data
ground_truth_data = [
    {"filename": "malware1.apk", "is_malicious": True, "source": "virustotal"},
    {"filename": "malware2.apk", "is_malicious": True, "source": "manual"},
    {"filename": "normal1.apk", "is_malicious": False, "source": "google_play"},
    {"filename": "normal2.apk", "is_malicious": False, "source": "google_play"},
]

# Upload ground truth
with open('ground_truth.json', 'w') as f:
    json.dump(ground_truth_data, f)

# Test evaluation
files = {'ground_truth_file': open('ground_truth.json', 'rb')}
response = requests.post('http://localhost:8000/evaluate/batch', files=files)
print("Evaluation Results:", json.dumps(response.json(), indent=2))

# Check metrics
response = requests.get('http://localhost:8000/evaluate/metrics')
print("\nCurrent Metrics:", json.dumps(response.json(), indent=2))

# Threshold analysis
response = requests.get('http://localhost:8000/evaluate/threshold-analysis')
print("\nThreshold Analysis:", json.dumps(response.json(), indent=2))