import csv
import re
import os
from datetime import datetime, timezone, timedelta

INPUT_DIR = "input"
OUTPUT_DIR = "output"

USN_FILE = os.path.join(INPUT_DIR, "usn_dump.csv")
MFT_FILE = os.path.join(INPUT_DIR, "host_mft.csv")

RAW_OUT = os.path.join(OUTPUT_DIR, "module2_raw.csv")
FILTER_OUT = os.path.join(OUTPUT_DIR, "module2_filtered.csv")
SMART_OUT = os.path.join(OUTPUT_DIR, "module2_smart.csv")

THRESHOLD_HOURS = 1.0

os.makedirs(OUTPUT_DIR, exist_ok=True)

def decode_frn(file_id_hex: str):
    if not file_id_hex:
        return None
    s = re.sub(r"[^0-9a-fA-F]", "", file_id_hex)
    if len(s) < 16:
        return None
    try:
        val = int(s[-16:], 16)
    except:
        return None
    entry = val & 0xFFFFFFFFFFFF
    seq = (val >> 48) & 0xFFFF
    return (entry, seq)


def trim_fraction(s: str):
    if "." not in s:
        return s
    before, after = s.split(".", 1)
    after = ''.join(x for x in after if x.isdigit())[:6].ljust(6, "0")
    return before + "." + after


def parse_usn_time(s: str):
    if not s:
        return None
    s = trim_fraction(s)
    for fmt in ["%d-%m-%Y %H:%M:%S.%f", "%d-%m-%Y %H:%M:%S",
                "%m-%d-%Y %H:%M:%S.%f", "%m-%d-%Y %H:%M:%S"]:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except:
            pass
    return None


def parse_mft_time(s: str):
    if not s:
        return None
    s = trim_fraction(s.split("+")[0])
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    except:
        return None

def load_usn():
    print(f"[+] Loading USN: {USN_FILE}")
    frn_map = {}

    with open(USN_FILE, "r", encoding="utf-16", errors="replace") as f:
        header = None
        for line in f:
            if line.lower().startswith("usn,"):
                header = line.strip().split(",")
                break
        if not header:
            print("[!] USN header not found!")
            return {}

        reader = csv.DictReader(f, fieldnames=header)
        count = 0

        for row in reader:
            file_id = row.get("File ID", "")
            ts = row.get("Time stamp", "")
            reason = row.get("Reason", "")
            name = row.get("File name", "")

            frn = decode_frn(file_id)
            if not frn:
                continue

            frn_map[frn] = {
                "usn_ts_str": ts,
                "usn_dt": parse_usn_time(ts),
                "reason": reason,
                "name": name,
            }
            count += 1

        print(f"[+] USN FRNs loaded: {count}")

    return frn_map

def smart_filter(mft_dt, usn_dt, diff_hours, parent_path):

    if not (mft_dt and usn_dt):
        return False, ""

    if not (mft_dt < usn_dt):
        return False, ""

    if diff_hours < (24 * 7):
        return False, ""

    suspicious_years = [1970, 1971, 1972, 1980, 1981, 1990, 1991, 1999]
    if mft_dt.year not in suspicious_years:
        return False, ""

    bad_paths = [
        "appdata", "temp", "cache", "microsoft", "bravesoftware",
        "edge", "discord", "system volume information",
        "nvidia", "programdata", "windows"
    ]
    pp = (parent_path or "").lower()
    if any(b in pp for b in bad_paths):
        return False, ""

    return True, "High-confidence timestomp (forged timestamp + huge backward jump)"

def scan_mft(usn_map):
    print(f"[+] Loading MFT: {MFT_FILE}")

    raw_rows = []
    filtered_rows = []
    smart_rows = []
    matched = 0

    with open(MFT_FILE, "r", encoding="utf-8-sig", errors="replace") as f_in:
        reader = csv.DictReader(f_in)

        for row in reader:
            try:
                entry = int(row["EntryNumber"])
                seq = int(row["SequenceNumber"])
            except:
                continue

            frn = (entry, seq)
            if frn not in usn_map:
                continue

            matched += 1
            usn = usn_map[frn]

            mft_dt = parse_mft_time(row.get("Created0x10", ""))
            usn_dt = usn["usn_dt"]
            parent_path = row.get("ParentPath", "")

            diff_hours = None
            flag_basic = False

            if mft_dt and usn_dt:
                diff_hours = abs((usn_dt - mft_dt).total_seconds()) / 3600
                if mft_dt < usn_dt and diff_hours >= THRESHOLD_HOURS:
                    flag_basic = True

            smart_flag, smart_reason = smart_filter(mft_dt, usn_dt, diff_hours, parent_path)

            entry_out = {
                "EntryNumber": entry,
                "SequenceNumber": seq,
                "ParentPath": parent_path,
                "MFT_Created": row.get("Created0x10", ""),
                "USN_Time": usn["usn_ts_str"],
                "USN_Reason": usn["reason"],
                "HourDifference": diff_hours,
                "FLAG_Timestomp": flag_basic,
                "FLAG_SMART": smart_flag,
                "SMART_Reason": smart_reason
            }

            raw_rows.append(entry_out)
            if flag_basic:
                filtered_rows.append(entry_out)
            if smart_flag:
                smart_rows.append(entry_out)

    print(f"[+] Matched FRNs: {matched}")
    print(f"[+] Smart Matches: {len(smart_rows)}")
    return raw_rows, filtered_rows, smart_rows

def save_output(raw_rows, filtered_rows, smart_rows):

    if raw_rows:
        with open(RAW_OUT, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=raw_rows[0].keys())
            w.writeheader()
            w.writerows(raw_rows)
        print(f"[+] RAW saved: {RAW_OUT}")

    if filtered_rows:
        with open(FILTER_OUT, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=filtered_rows[0].keys())
            w.writeheader()
            w.writerows(filtered_rows)
        print(f"[+] FILTERED saved: {FILTER_OUT}")

    if smart_rows:
        with open(SMART_OUT, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=smart_rows[0].keys())
            w.writeheader()
            w.writerows(smart_rows)
        print(f"[+] SMART saved: {SMART_OUT}")

if __name__ == "__main__":
    print("\n=== Module 2 Final (SMART VERSION) ===\n")
    usn_map = load_usn()
    raw, filtered, smart = scan_mft(usn_map)
    save_output(raw, filtered, smart)
    print("\n[+] Module 2 finished.\n")