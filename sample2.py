import re
from datetime import datetime

THREAT_RULES = {
    "Failed login attempt." : ("T1110", "Brute Force Attack", "Credential Access"),
    "New user account created." : ("T1136", "Create Account", "Persistence"),
    "Scheduled task created." : ("T1053", "Scheduled Task/Job", "Persistence"),
    "Explicit credential use detected." : ("T1078", "Valid Accounts", "Credential Access"),
    "New process created." : ("T1057", "Process Discovery", "Discovery"),
    "PowerShell script executed." : ("T1059", "Command and Scripting Interpreter", "Execution"),
}

INTERNAL_IPS = ("192.168.", "10.", "172.")

def is_external_ip(ip):
    if ip == "N/A":
        return False
    if ip.startswith(INTERNAL_IPS):
        return False
    return True


def parse_log_line(line):
    pattern = r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\w+)\s+(.+?)(?:\s+User: (\w+))?(?:\s+IP: ([\d.]+))?$"
    match = re.match(pattern, line)
    if not match:
        return None
    return {
        "date": match.group(1),
        "time": match.group(2),
        "type": match.group(3),
        "description": match.group(4).strip(),
        "user": match.group(5) if match.group(5) else "N/A",
        "ip": match.group(6) if match.group(6) else "N/A"
    }


def analyze_log_line(events):
    red_flags = []
    failed_login_attempts = {}

    for e in events:
        threat_label = None
        mitre_id = None
        category = None

        for keyword, (id, label, cat) in THREAT_RULES.items():
            if keyword.lower() in e["description"].lower():
                threat_label = label
                mitre_id = id
                category = cat
                break

        if "Failed login attempt" in e["description"] and e["ip"] != "N/A":
            if e["ip"] not in failed_login_attempts:
                failed_login_attempts[e["ip"]] = []
            failed_login_attempts[e["ip"]].append(f"{e['date']} {e['time']}")

        external_flag = is_external_ip(e["ip"]) and e["type"] in ("WARNING", "ERROR")

        if threat_label or external_flag:
            red_flags.append({
                **e,
                "threat_label": threat_label or "Suspicious External IP",
                "mitre_id": mitre_id,
                "category": category
            })

    return red_flags, failed_login_attempts


def write_report(red_flags, failed_login_attempts, total_events, output_file):
    category_counts = {}
    for flag in red_flags:
        cat = flag["category"] or "Unknown"
        if cat not in category_counts:
            category_counts[cat] = 0
        category_counts[cat] += 1

    brute_force = {}
    for ip, times in failed_login_attempts.items():
        if len(times) >= 3:
            brute_force[ip] = times

    with open(output_file, "w") as f:

        f.write("=" * 55 + "\n")
        f.write("  LOG THREAT REPORT\n")
        f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 55 + "\n\n")

        f.write("--- SUMMARY ---\n")
        f.write(f"  Total events scanned : {total_events}\n")
        f.write(f"  Red flags found      : {len(red_flags)}\n")
        f.write(f"  Brute force IPs      : {len(brute_force)}\n\n")

        f.write("--- FLAGS BY CATEGORY ---\n")
        for cat, count in category_counts.items():
            f.write(f"  {cat:<30} {count} event(s)\n")

        if brute_force:
            f.write("\n--- BRUTE FORCE DETECTED ---\n")
            for ip, times in brute_force.items():
                f.write(f"  IP: {ip}  ({len(times)} failed attempts)\n")
                for t in times:
                    f.write(f"    {t}\n")

        f.write("\n--- ALL RED FLAGS ---\n")
        for flag in red_flags:
            f.write("\n")
            f.write(f"  Date/Time : {flag['date']} {flag['time']}\n")
            f.write(f"  Level     : {flag['type']}\n")
            f.write(f"  Event     : {flag['description']}\n")
            f.write(f"  User      : {flag['user']}\n")
            f.write(f"  IP        : {flag['ip']}\n")
            f.write(f"  Threat    : {flag['threat_label']}\n")
            if flag["mitre_id"]:
                f.write(f"  MITRE ID  : {flag['mitre_id']}\n")
            if flag["category"]:
                f.write(f"  Category  : {flag['category']}\n")
            f.write("  " + "-" * 40 + "\n")

    print(f"\n  Report saved to -> {output_file}")


def main():
    log_file = "sample2.log"
    report_file = "report2.txt"

    print("=" * 55)
    print("  LOG PARSER")
    print("=" * 55)
    print(f"\n  Reading: {log_file}\n")

    events = []
    with open(log_file, "r") as f:
        for line in f:
            parsed = parse_log_line(line.strip())
            if parsed:
                events.append(parsed)

    red_flags, failed_login_attempts = analyze_log_line(events)

    print("-" * 55)
    for flag in red_flags:
        print(f"  [{flag['type']}] {flag['date']} {flag['time']}")
        print(f"  {flag['description']}")
        print(f"  User: {flag['user']}  |  IP: {flag['ip']}")
        print(f"  Threat   : {flag['threat_label']}")
        if flag["mitre_id"]:
            print(f"  MITRE ID : {flag['mitre_id']}")
        print("-" * 55)

    print(f"\n  Total events scanned : {len(events)}")
    print(f"  Red flags found      : {len(red_flags)}")

    write_report(red_flags, failed_login_attempts, len(events), report_file)


if __name__ == "__main__":
    main()
