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

```

###2. InstallationInstall all required Python dependencies:

```bash
pip install -r requirements.txt

```

*(Note: `requirements.txt` should contain `pandas`, `scikit-learn`, `python-evtx`, etc.)*

###3. Data PreparationPlace the forensic artifacts into the designated `input/` directory:

| Artifact | Source Tool | Required File(s) |
| --- | --- | --- |
| **Event Logs** | `EvtxECmd` or direct extraction | `Security.evtx`, `System.evtx` |
| **MFT** | `MFTECmd` | `host_mft.csv` |
| **USN Journal** | `fsutil usn readjournal` | `usn_dump.csv` (Ensure UTF-16 encoding is handled) |

###4. Execution OrderRun the modules sequentially. The output of each step is placed in the `output/` directory and consumed by the next step.

| Step | Command | Purpose |
| --- | --- | --- |
| **1. Collect Rules** | `python module1_log_parser.py` | Extracts suspicious EIDs. |
| **2. Collect Timestamps** | `python module2_timestamp_compare.py` | Detects MFT/USN inconsistencies. |
| **3. Detect Patterns** | `python module3_anomaly_detector.py` | Converts logs to features and applies Isolation Forest. |
| **4. Validate Findings** | `python correlation_engine.py` | Runs the 2-out-of-3 rule and generates the final report. |

---

##📄 Final ReportThe definitive output is found in the `output/` folder:

* **`correlation_report.json`**: The final, detailed report showing every suspicious file and the evidence from Modules 1, 2, and 3 that corroborates it. This is the **High-Confidence Evidence** provided to the analyst.
* **`correlation_report.csv`**: A summary table for quick review, listing the file path, the USN time, and the number of modules (2 or 3) that confirmed the anomaly.
