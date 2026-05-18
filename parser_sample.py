import re
import os
import argparse
from datetime import datetime
from collections import defaultdict

# --- Threat rules: keyword → (label, MITRE technique, category) ---
THREAT_RULES = {
    "Failed login attempt":       ("Failed login attempt",        "T1110   - Brute Force",                  "Credential Access"),
    "Explicit credential use":    ("Explicit credential use",     "T1134   - Access Token Manipulation",    "Credential Access"),
    "New user account created":   ("New user account created",    "T1136   - Create Account",               "Persistence"),
    "Scheduled task created":     ("Scheduled task created",      "T1053   - Scheduled Task",               "Persistence"),
    "PowerShell script executed": ("PowerShell script executed",  "T1059.001 - PowerShell",                 "Execution"),
    "New process created":        ("New process created",         "T1059   - Command Interpreter",          "Execution"),
}

INTERNAL_PREFIXES = ("192.168.", "10.", "172.")

def is_external(ip):
    if ip == "N/A":
        return False
    return not any(ip.startswith(prefix) for prefix in INTERNAL_PREFIXES)

def parse_line(line):
    """Parse a single log line into structured fields."""
    pattern = r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\w+)\s+(.+?)(?:\s+User: (\w+))?(?:\s+IP: ([\d.]+))?$"
    match = re.match(pattern, line)
    if not match:
        return None
    return {
        "timestamp":  f"{match.group(1)} {match.group(2)}",
        "log_level":  match.group(3),
        "message":    match.group(4).strip(),
        "user":       match.group(5) if match.group(5) else "N/A",
        "ip_address": match.group(6) if match.group(6) else "N/A",
    }

def analyse(events):
    """Flag threats, detect brute force, and flag external IPs."""
    flagged        = []
    failed_logins  = defaultdict(list)  # ip → list of timestamps

    for e in events:
        threat_label = None
        mitre        = None
        category     = None

        # Match against threat rules
        for keyword, (label, mitre_code, cat) in THREAT_RULES.items():
            if keyword.lower() in e["message"].lower():
                threat_label = label
                mitre        = mitre_code
                category     = cat
                break

        # Track failed logins per IP for brute force detection
        if threat_label == "Failed login attempt" and e["ip_address"] != "N/A":
            failed_logins[e["ip_address"]].append(e["timestamp"])

        # Flag external IPs on any WARNING or ERROR line
        external_flag = is_external(e["ip_address"]) and e["log_level"] in ("WARNING", "ERROR")

        if threat_label or external_flag:
            flagged.append({
                **e,
                "threat":   threat_label or "Suspicious external IP",
                "mitre":    mitre or "T1071 - Application Layer Protocol",
                "category": category or "Command and Control",
                "external": is_external(e["ip_address"]),
            })

    return flagged, failed_logins

def write_report(flagged, failed_logins, total_lines, output_path):
    category_counts = defaultdict(int)
    event_counts    = defaultdict(int)

    for e in flagged:
        category_counts[e["category"]] += 1
        event_counts[e["threat"]]      += 1

    brute_force_ips = {ip: ts for ip, ts in failed_logins.items() if len(ts) >= 3}

    with open(output_path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  THREAT DETECTION REPORT\n")
        f.write(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        f.write("--- SUMMARY ---\n")
        f.write(f"  Total log lines scanned : {total_lines}\n")
        f.write(f"  Threats flagged         : {len(flagged)}\n")
        f.write(f"  Brute force IPs         : {len(brute_force_ips)}\n\n")

        f.write("--- DETECTIONS BY CATEGORY ---\n")
        for cat, count in sorted(category_counts.items()):
            f.write(f"  {cat:<30} {count} event(s)\n")

        f.write("\n--- DETECTIONS BY TYPE ---\n")
        for threat, count in sorted(event_counts.items(), key=lambda x: -x[1]):
            f.write(f"  {threat:<40} x{count}\n")

        if brute_force_ips:
            f.write("\n--- BRUTE FORCE DETECTED ---\n")
            for ip, timestamps in brute_force_ips.items():
                f.write(f"  IP: {ip}  —  {len(timestamps)} failed attempts\n")
                for ts in timestamps:
                    f.write(f"    {ts}\n")

        f.write("\n--- DETAILED FINDINGS ---\n")
        for e in flagged:
            ext = " [EXTERNAL IP]" if e["external"] else ""
            f.write(f"\n  [{e['category']}] {e['timestamp']}{ext}\n")
            f.write(f"  Level    : {e['log_level']}\n")
            f.write(f"  Message  : {e['message']}\n")
            f.write(f"  User     : {e['user']}\n")
            f.write(f"  IP       : {e['ip_address']}\n")
            f.write(f"  Threat   : {e['threat']}\n")
            f.write(f"  MITRE    : {e['mitre']}\n")
            f.write("  " + "-" * 40 + "\n")

    print(f"\n  Report saved → {output_path}")

def main():
    arg_parser = argparse.ArgumentParser(description="Log File Threat Parser")
    arg_parser.add_argument("--file",   default="sample.log",  help="Log file to scan")
    arg_parser.add_argument("--output", default="report.txt",  help="Output report file")
    args = arg_parser.parse_args()

    print("\n" + "=" * 60)
    print("  LOG FILE THREAT PARSER")
    print("=" * 60)

    if not os.path.exists(args.file):
        print(f"  [!] File not found: {args.file}")
        return

    print(f"\n  Scanning: {args.file}\n")

    events = []
    with open(args.file, "r") as f:
        for line in f:
            parsed = parse_line(line)
            if parsed:
                events.append(parsed)

    flagged, failed_logins = analyse(events)

    # Print to terminal
    print("-" * 60)
    for e in flagged:
        ext = " [EXTERNAL IP]" if e["external"] else ""
        print(f"  [{e['log_level']}] {e['timestamp']}{ext}")
        print(f"  {e['message']}")
        print(f"  User: {e['user']}  |  IP: {e['ip_address']}")
        print(f"  Threat : {e['threat']}")
        print(f"  MITRE  : {e['mitre']}")
        print("-" * 60)

    # Brute force summary
    brute_force_ips = {ip: ts for ip, ts in failed_logins.items() if len(ts) >= 3}
    if brute_force_ips:
        print("\n  [!] BRUTE FORCE DETECTED:")
        for ip, timestamps in brute_force_ips.items():
            print(f"  IP {ip} had {len(timestamps)} failed login attempts")

    print(f"\n  Total lines scanned : {len(events)}")
    print(f"  Threats flagged     : {len(flagged)}")

    write_report(flagged, failed_logins, len(events), args.output)

if __name__ == "__main__":
    main()
