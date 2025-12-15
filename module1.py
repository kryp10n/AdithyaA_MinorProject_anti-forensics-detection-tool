import os
import csv
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_record_xml_view

INPUT_DIR = "input"
OUTPUT_DIR = "output"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "module_1output.csv")

os.makedirs(OUTPUT_DIR, exist_ok=True)

XML_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Rule Table
EVENT_IDS = [
    1100, 1102, 104, 4616,
    4672, 4688, 4697,
    4624, 4625,
    6005, 6006
]

def parse_evtx_file(filepath, max_records=0):
    extracted = []
    print(f"Parsing {filepath}...")

    try:
        with Evtx(filepath) as log:
            for i, record in enumerate(log.records()):
                if max_records and i >= max_records:
                    break

                try:
                    xml_str = evtx_record_xml_view(record)
                    root = ET.fromstring(xml_str)

                    eid_elem = root.find(f".//{XML_NS}EventID")
                    if eid_elem is None:
                        continue

                    eid = int(eid_elem.text)
                    if eid not in EVENT_IDS:
                        continue

                    timestamp = record.timestamp()

                    comp = root.find(f".//{XML_NS}Computer")
                    computer = comp.text if comp is not None else "-"

                    data_dict = {}
                    for d in root.findall(f".//{XML_NS}Data"):
                        name = d.get("Name")
                        value = d.text.strip() if (d.text and d.text.strip()) else "-"
                        data_dict[name] = value

                    extracted.append({
                        "EventID": eid,
                        "TimeCreated": timestamp,
                        "SourceLog": os.path.basename(filepath),
                        "Computer": computer,
                        "User": data_dict.get("SubjectUserName") or data_dict.get("TargetUserName") or "-",
                        "ProcessId": data_dict.get("ProcessId", "-"),
                        "Target": data_dict.get("NewProcessName") or data_dict.get("ServiceName") or "-",
                        "CommandLine": data_dict.get("CommandLine", "-")
                    })

                except Exception:
                    continue

    except Exception as e:
        print(f"[!] Error reading {filepath}: {e}")

    print(f"Extracted {len(extracted)} events from {filepath}")
    return extracted

def save_to_csv(data):
    if not data:
        print("[!] No events extracted.")
        return

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)

    print(f"Saved results to {OUTPUT_FILE}")

def find_evtx_files():
    if not os.path.isdir(INPUT_DIR):
        print(f"[!] Input folder '{INPUT_DIR}' not found!")
        return []

    return [
        os.path.join(INPUT_DIR, f)
        for f in os.listdir(INPUT_DIR)
        if f.lower().endswith(".evtx")
    ]

def main():
    print("\n=== Module 1 — Windows Event Log Parser ===\n")

    evtx_files = find_evtx_files()
    if not evtx_files:
        print("No .evtx files found in ./input/")
        return

    all_events = []
    for evtx_file in evtx_files:
        all_events.extend(parse_evtx_file(evtx_file))

    save_to_csv(all_events)
    print("\n[+] Module 1 Completed.\n")

if __name__ == "__main__":
    main()