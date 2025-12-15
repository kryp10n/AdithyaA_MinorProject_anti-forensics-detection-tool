# 🛡️ Automated Anti-Forensics Correlation Engine

## Project Summary

This project implements a multi-layered system designed to automatically detect anti-forensic techniques (like log clearing and timestomping) in Windows 10/11 forensic images. The system integrates three independent analysis modules and uses a final Correlation Engine to validate findings, dramatically reducing false positives and improving the efficiency of forensic investigations.

### The Core Novelty (The 2-out-of-3 Rule)

The system flags an incident as **High-Confidence Evidence** only when a suspicious event or file is independently corroborated (matched temporally and/or by entity) by **two or more** of the three modules.

---

## 🛠️ Architecture and Modules

| Module | Core Function | Artifacts Analyzed | Output |
| :--- | :--- | :--- | :--- |
| **Module 1 (Rule-Based Log)** | Extracts high-value Windows Event IDs (Log Clears, Time Changes, Process Creations). | Security.evtx, System.evtx | `module1_output.csv` (Filtered list of known suspicious events) |
| **Module 2 (Artifact Comparison)** | Detects **Timestomping** by comparing the file's claimed **MFT Creation Time** (the lie) against the verified **USN Journal Transaction Time** (the truth). | MFT (`host_mft.csv`), USN Journal (`usn_dump.csv`) | `module2_smart.csv` (High-confidence forgery candidates, filtered for system noise) |
| **Module 3 (ML Anomaly Detection)** | Uses **Isolation Forest** to flag statistically anomalous time windows in the overall volume and composition of event log activity. | Raw .evtx logs (processed into Time Window Feature Vectors) | `module3_anomalies.csv` (Time windows with high anomaly scores) |
| **Correlation Engine (The Brain)** | **Automated Validation.** Correlates the output of all three modules (M1, M2, M3) based on shared time and file identifiers (FRN/Path). | All module output files | `correlation_report.json` |

---

## 🚀 Getting Started

### 1. Prerequisites

This project requires Python 3.11.9.

```bash
# We recommend using a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
