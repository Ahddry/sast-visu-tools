import sys
import subprocess
from datetime import datetime
import requests
import json
from tabulate import tabulate, SEPARATING_LINE
from collections import Counter

def summarize_findings(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)

    # Add date_time attribute to the JSON data
    data["date_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save the updated JSON data back to the file
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

    results = data.get("results", [])
    severity_map = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}
    severity_count = Counter(severity_map[result["extra"]["severity"]] for result in results)

    all_severities = ["High", "Medium", "Low"]
    severity_table = [[sev, severity_count.get(sev, 0)] for sev in all_severities]
    severity_table.append(SEPARATING_LINE)
    severity_table.append(["Total", sum(severity_count.values())])

    with open("semgrep-results-summary.txt", "w") as output_file:
        # Severity count
        print("\nResults summary:")
        print(tabulate(severity_table, headers=["Severity", "Count"], tablefmt="simple"))
        output_file.write("Results summary:\n")
        output_file.write(tabulate(severity_table, headers=["Severity", "Count"], tablefmt="simple") + "\n")
        output_file.write("\nScan date: " + data["date_time"] + "\n")

        tech_count = Counter(
            tech
            for result in results
            for tech in result["extra"]["metadata"].get("technology", [])
        )
        tech_table = [[k, v] for k, v in tech_count.most_common()]
        tech_table.append(SEPARATING_LINE)
        tech_table.append(["Total", sum(tech_count.values())])
        output_file.write("\nLanguages:\n")
        output_file.write(tabulate(tech_table, headers=["Technology", "Count"], tablefmt="simple") + "\n")

        owasp_top_10_2021 = [
            "A01:2021 - Broken Access Control",
            "A02:2021 - Cryptographic Failures",
            "A03:2021 - Injection",
            "A04:2021 - Insecure Design",
            "A05:2021 - Security Misconfiguration",
            "A06:2021 - Vulnerable and Outdated Components",
            "A07:2021 - Identification and Authentication Failures",
            "A08:2021 - Software and Data Integrity Failures",
            "A09:2021 - Security Logging and Monitoring Failures",
            "A10:2021 - Server-Side Request Forgery (SSRF)"
        ]
        owasp_top_10_2017 = [
            "A01:2017 - Injection",
            "A02:2017 - Broken Authentication",
            "A03:2017 - Sensitive Data Exposure",
            "A04:2017 - XML External Entities (XXE)",
            "A05:2017 - Broken Access Control",
            "A06:2017 - Security Misconfiguration",
            "A07:2017 - Cross-Site Scripting (XSS)",
            "A08:2017 - Insecure Deserialization",
            "A09:2017 - Using Components with Known Vulnerabilities",
            "A10:2017 - Insufficient Logging & Monitoring"
        ]
        owasp_count = Counter(owasp for result in results for owasp in result["extra"]["metadata"].get("owasp", []))
        owasp_table_2021 = [[]]
        for result in results:
            for owasp in result["extra"]["metadata"].get("owasp", []):
                # Normalize OWASP entries by replacing "-" with " - "
                normalized_owasp = owasp.replace("2021-", "2021 - ").replace("2017-", "2017 - ").replace("A1", "A01").replace("A2", "A02").replace("A3", "A03").replace("A4", "A04").replace("A5", "A05").replace("A6", "A06").replace("A7", "A07").replace("A8", "A08").replace("A9", "A09")
                owasp_count[normalized_owasp] += 1
                owasp_table_2021 = [[owasp, owasp_count.get(owasp, 0)] for owasp in owasp_top_10_2021]
        owasp_table_2017 = [[owasp, owasp_count.get(owasp, 0)] for owasp in owasp_top_10_2017 if owasp_count.get(owasp, 0) > 0]
        output_file.write("\nOWASP Top 10:\n")
        if owasp_table_2017:
            owasp_table_2021.append(SEPARATING_LINE)
            owasp_table_2021.extend(owasp_table_2017)
        output_file.write(tabulate(owasp_table_2021, headers=["OWASP", "Count"], tablefmt="simple") + "\n")


        cwe_count = Counter(
            cwe
            for result in results
            for cwe in (result["extra"]["metadata"].get("cwe", []) if isinstance(result["extra"]["metadata"].get("cwe", []), list) else [result["extra"]["metadata"].get("cwe", [])])
        )
        cwe_table = [[k, v] for k, v in cwe_count.items()]
        output_file.write("\nCWE:\n")
        output_file.write(tabulate(cwe_table, headers=["CWE", "Count"], tablefmt="simple") + "\n")
        cwe2022_top25_count = sum(1 for result in results if result["extra"]["metadata"].get("cwe2022-top25", False))
        output_file.write("\nIncluding " + str(cwe2022_top25_count) + " " + "CWE top 25.\n")

        file_count = Counter(result["path"] for result in results)
        file_table = [[k, v] for k, v in file_count.most_common()]
        file_table.append(SEPARATING_LINE)
        file_table.append(["Total", sum(file_count.values())])
        output_file.write("\nFiles with vulnerabilities:\n")
        output_file.write(tabulate(file_table, headers=["File", "Count"], tablefmt="simple") + "\n")

        vuln_class_count = Counter(
            vuln_class
            for result in results
            for vuln_class in result["extra"]["metadata"].get("vulnerability_class", [])
        )
        vuln_class_table = [[k, v] for k, v in vuln_class_count.most_common()]
        vuln_class_table.append(SEPARATING_LINE)
        vuln_class_table.append(["Total", sum(vuln_class_count.values())])
        output_file.write("\nVulnerability classes:\n")
        output_file.write(tabulate(vuln_class_table, headers=["Vulnerability class", "Count"], tablefmt="simple"))
        print("\nResults summary saved to semgrep-results-summary.txt")

print("Starting custom semgrep scan...")

# Get the current date and time
current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Determine the directory to create
if len(sys.argv) == 3:
    target_dir = f"{sys.argv[1]}/{current_datetime}_semgrep-report"
elif len(sys.argv) == 2:
    target_dir = f"./{current_datetime}_semgrep-report"
else:
    target_dir = f"./{current_datetime}_semgrep-report"

# Download the patched-codes-semgrep-rules.yml file
rules_url = "https://raw.githubusercontent.com/patched-codes/semgrep-rules/refs/heads/main/patched-codes-semgrep-rules.yml"
rules_file = "patched-codes-semgrep-rules.yml"
response = requests.get(rules_url)
if response.status_code == 200:
    with open(rules_file, 'wb') as file:
        file.write(response.content)
else:
    print("Error: Failed to download patched-codes-semgrep-rules.yml")
    sys.exit(1)

# Check if semgrep is installed
if subprocess.call(["which", "semgrep"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
    print("Error: semgrep is not installed")
    sys.exit(1)

# Determine the path argument for semgrep scan
if len(sys.argv) == 3:
    scan_path = sys.argv[2]
elif len(sys.argv) == 2:
    scan_path = sys.argv[1]
else:
    scan_path = "."

# Run semgrep scan
subprocess.run(["semgrep", "scan","-q" , "--config", "auto", "--config", ".", "--json", "-o", "semgrep-report.json", scan_path])

# Execute the visu-semgrep script
try:
    summarize_findings("semgrep-report.json")
except Exception as e:
    print(f"Error: Failed to execute visu_semgrep_ci: {e}")
    sys.exit(1)

print("Process completed successfully")