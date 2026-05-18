import re
import os
from datetime import datetime
from collections import defaultdict

SUSPICIOUS_PATTERNS = {
    "Base64 encoded payload":       r"FromBase64String|base64",
    "Credential harvesting":        r"PromptForCredential|GetNetworkCredential",
    "In-memory execution":          r"Invoke-Expression|IEX|\[scriptblock\]::create",
    "Obfuscated/compressed payload":r"GzipStream|MemoryStream|Decompress",
    "Fake login prompt":            r"Invoke-LoginPrompt|Windows Security",
    "Remote command execution":     r"Execute a Remote Command",
    "Download cradle":              r"Net\.WebClient|DownloadString|WebRequest",
}

MITRE_MAP = {
    "Base64 encoded payload":        "T1027   - Obfuscated Files or Information",
    "Credential harvesting":         "T1056   - Input Capture / Credential Prompt",
    "In-memory execution":           "T1059.001 - PowerShell",
    "Obfuscated/compressed payload": "T1027   - Obfuscated Files or Information",
    "Fake login prompt":             "T1056.002 - GUI Input Capture",
    "Remote command execution":      "T1059.001 - PowerShell",
    "Download cradle":               "T1105   - Ingress Tool Transfer",
}

def parse_blocks(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    blocks = re.split(r'(?=(?:Warning|Information|Error)\t)', content)
    return [b.strip() for b in blocks if "4104" in b]

def analyse_block(block):
    hits = []
    for label, pattern in SUSPICIOUS_PATTERNS.items():
        if re.search(pattern, block, re.IGNORECASE):
            hits.append(label)
    return hits

def extract_timestamp(block):
    match = re.search(r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}', block)
    return match.group(0) if match else "Unknown"

def write_report(results, output_path):
    tactic_counts = defaultdict(int)
    for r in results:
        for hit in r["hits"]:
            tactic_counts[hit] += 1

    with open(output_path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  POWERSHELL THREAT DETECTION REPORT\n")
        f.write(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        f.write("--- SUMMARY ---\n")
        f.write(f"  Event ID 4104 blocks analysed : {len(results)}\n")
        f.write(f"  Suspicious blocks detected    : {sum(1 for r in results if r['hits'])}\n\n")

        f.write("--- DETECTIONS BY TYPE ---\n")
        for tactic, count in sorted(tactic_counts.items(), key=lambda x: -x[1]):
            f.write(f"  {tactic:<35} x{count}\n")
            f.write(f"  {'MITRE: ' + MITRE_MAP[tactic]:<35}\n\n")

        f.write("\n--- DETAILED FINDINGS ---\n")
        for i, r in enumerate(results, 1):
            if not r["hits"]:
                continue
            f.write(f"\n  [Event {i}] Timestamp: {r['timestamp']}\n")
            f.write(f"  Event ID : 4104 — PowerShell Script Block Logged\n")
            f.write("  Detections:\n")
            for hit in r["hits"]:
                f.write(f"    - {hit}\n")
                f.write(f"      MITRE: {MITRE_MAP[hit]}\n")
            f.write("  " + "-" * 40 + "\n")

    print(f"\n  Report saved → {output_path}")

def main():
    file_path   = "phish.log"
    output_path = "phish_report.txt"

    print("\n" + "=" * 60)
    print("  POWERSHELL LOG THREAT PARSER")
    print("=" * 60)

    if not os.path.exists(file_path):
        print(f"  [!] File not found: {file_path}")
        return

    print(f"\n  Scanning: {file_path}")
    blocks  = parse_blocks(file_path)
    print(f"  Event ID 4104 blocks found: {len(blocks)}")

    results = []
    for block in blocks:
        hits = analyse_block(block)
        results.append({
            "timestamp": extract_timestamp(block),
            "hits":      hits
        })
        if hits:
            print(f"\n  [SUSPICIOUS] {extract_timestamp(block)}")
            for h in hits:
                print(f"    → {h} | {MITRE_MAP[h]}")

    write_report(results, output_path)

if __name__ == "__main__":
    main()