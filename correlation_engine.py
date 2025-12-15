import os
import csv
import json
from datetime import timedelta
import pandas as pd

INPUT_FOLDER = "output"
OUTPUT_FILE_CSV = "output/correlation_report.csv"
OUTPUT_FILE_JSON = "output/correlation_report.json"

TIME_WINDOW_MINUTES = 10

def parse_time(t):
    if pd.isna(t) or not t:
        return None

    t = str(t)

    try:
        if t[2] == "-" and t[5] == "-":
            return pd.to_datetime(t, utc=True, dayfirst=True)

        return pd.to_datetime(t, utc=True)

    except:
        return None

def load_csv(path):
    if not os.path.exists(path):
        print(f"[!] Missing file: {path}")
        return pd.DataFrame()

    df = pd.read_csv(path)
    print(f"[+] Loaded {len(df)} rows from {path}")
    return df


def load_all_modules():
    mod1 = load_csv(os.path.join(INPUT_FOLDER, "module1_output.csv"))
    mod2 = load_csv(os.path.join(INPUT_FOLDER, "module2_smart.csv"))
    mod3 = load_csv(os.path.join(INPUT_FOLDER, "module3_anomalies.csv"))
    return mod1, mod2, mod3

def correlate(mod1, mod2, mod3):
    print("\n=== Running Correlation Engine ===\n")

    if mod1.empty and mod2.empty and mod3.empty:
        print("[!] No input available. Exiting.")
        return []

    if not mod1.empty:
        mod1["Time"] = mod1["TimeCreated"].apply(parse_time)

    if not mod2.empty:
        mod2["Time"] = mod2["USN_Time"].apply(parse_time)

    if not mod3.empty:
        mod3["Time"] = mod3["window_start"].apply(parse_time)

    results = []
    window = timedelta(minutes=TIME_WINDOW_MINUTES)

    print("[+] Correlating evidence across modules...")

    for _, row2 in mod2.iterrows():
        t2 = row2.get("Time")
        if t2 is None:
            continue

        t2 = pd.Timestamp(t2).tz_convert("UTC")

        evidence = {
            "timestomp_entry": f"{row2.get('EntryNumber')}-{row2.get('SequenceNumber')}",
            "file_path": row2.get("ParentPath", "-"),
            "mft_created": row2.get("MFT_Created", "-"),
            "usn_time": row2.get("USN_Time", "-"),
            "smart_reason": row2.get("SMART_Reason", "-"),
            "module1_match": [],
            "module3_match": []
        }

        for _, r1 in mod1.iterrows():
            t1 = r1.get("Time")
            if t1 is None:
                continue

            t1 = pd.Timestamp(t1).tz_convert("UTC")

            if abs(t1 - t2) <= window:
                evidence["module1_match"].append({
                    "EventID": r1.get("EventID"),
                    "User": r1.get("User"),
                    "Process": r1.get("Target"),
                    "Time": str(t1)
                })

        for _, r3 in mod3.iterrows():
            if r3.get("anomaly_flag") != 1:
                continue

            t3 = r3.get("Time")
            if t3 is None:
                continue

            t3 = pd.Timestamp(t3).tz_convert("UTC")

            if abs(t3 - t2) <= window:
                evidence["module3_match"].append({
                    "window_start": r3.get("window_start"),
                    "score": r3.get("score")
                })

        modules_hit = 1
        if evidence["module1_match"]:
            modules_hit += 1
        if evidence["module3_match"]:
            modules_hit += 1

        if modules_hit >= 2:
            evidence["modules_hit"] = modules_hit
            results.append(evidence)

    print(f"[+] Correlation complete. Final correlated events: {len(results)}")
    return results

def save_report(results):
    if not results:
        print("[!] No correlated events. Report not created.")
        return

    with open(OUTPUT_FILE_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
    print(f"[+] JSON report saved: {OUTPUT_FILE_JSON}")

    rows = []
    for r in results:
        rows.append({
            "timestomp_entry": r["timestomp_entry"],
            "file_path": r["file_path"],
            "usn_time": r["usn_time"],
            "mft_created": r["mft_created"],
            "smart_reason": r["smart_reason"],
            "module1_hits": len(r["module1_match"]),
            "module3_hits": len(r["module3_match"]),
            "modules_hit": r["modules_hit"]
        })

    df = pd.DataFrame(rows)
    df.to_csv(OUTPUT_FILE_CSV, index=False, encoding="utf-8")
    print(f"[+] CSV report saved: {OUTPUT_FILE_CSV}")

if __name__ == "__main__":
    mod1, mod2, mod3 = load_all_modules()
    results = correlate(mod1, mod2, mod3)
    save_report(results)
    print("\n[✓] Correlation Engine Completed.\n")