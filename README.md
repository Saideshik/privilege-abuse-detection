# Privilege Abuse Detection (PAD) – Reference Implementation

This repository contains a **lab/reference** detection engineering implementation to identify **privileged account abuse** across:
- Windows process/logon events
- Linux sudo/auth events
- Cloud IAM activity (AWS CloudTrail-style)

> Note: This is a reference/starter implementation intended for learning and extension. It uses simulated sample logs under `data/`.

## What it detects
- Unusual admin activity outside baseline login hours
- Rare commands for a given admin
- New host access by a privileged identity
- Suspicious PowerShell patterns (e.g., encoded commands)
- Cross-system “privilege jumps” (basic correlation)

## MITRE ATT&CK (examples)
- T1078 – Valid Accounts
- T1068 – Exploitation for Privilege Escalation
- T1059 – Command and Scripting Interpreter
- T1548 – Abuse Elevation Control Mechanism

## Quickstart
```bash
python -m venv .venv
source .venv/bin/activate  # (Windows: .venv\Scripts\activate)
pip install -e .
pad run --windows data/sample_windows_events.jsonl --linux data/sample_linux_auth.log --cloud data/sample_cloudtrail.jsonl
```

## Output
The CLI prints JSON alerts with:
- normalized event
- anomaly score
- detection reasons
- MITRE technique mapping
- risk score (privilege × anomaly × asset criticality)

## Extend
- Replace sample logs with real ingestion (Winlogbeat/Filebeat/CloudTrail)
- Swap anomaly scoring for Isolation Forest per admin
- Add alert suppression + tuning + evaluation metrics
