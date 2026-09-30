import json
from datetime import datetime

def export_json_report(data, filename="scan_report.json"):
    """Export scan results to a timestamped JSON file."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "scan_data": data
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    print(f"\n[+] Scan report successfully saved to '{filename}'")