import argparse
import json
from tabulate import tabulate, SEPARATING_LINE
from collections import Counter

def summarize_findings(file_path, args):
    with open(file_path, 'r') as file:
        data = json.load(file)

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

        # Option -l : Languages used
        if args.languages:
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

        # Option -o : OWASP Top 10 vulnerabilities
        if args.owasp:
            owasp_top_10 = [
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
            owasp_count = Counter(owasp for result in results for owasp in result["extra"]["metadata"].get("owasp", []))
            owasp_table = [[owasp, owasp_count.get(owasp, 0)] for owasp in owasp_top_10]
            output_file.write("\nOWASP Top 10:\n")
            output_file.write(tabulate(owasp_table, headers=["OWASP", "Count"], tablefmt="simple") + "\n")

        # Option -c : CWE vulnerabilities
        if args.cwe:
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

        # Option -f : Vulnerable files
        if args.files:
            file_count = Counter(result["path"] for result in results)
            file_table = [[k, v] for k, v in file_count.most_common()]
            file_table.append(SEPARATING_LINE)
            file_table.append(["Total", sum(file_count.values())])
            output_file.write("\nFiles with vulnerabilities:\n")
            output_file.write(tabulate(file_table, headers=["File", "Count"], tablefmt="simple") + "\n")
        print("\nResults summary saved to semgrep-results-summary.txt")

        # Option -C : Vulnerability class
        if args.vuln_class:
            vuln_class_count = Counter(
                vuln_class
                for result in results
                for vuln_class in result["extra"]["metadata"].get("vulnerability_class", [])
            )
            vuln_class_table = [[k, v] for k, v in vuln_class_count.most_common()]
            vuln_class_table.append(SEPARATING_LINE)
            vuln_class_table.append(["\033[1mTotal\033[0m", "\033[1m" + str(sum(vuln_class_count.values())) + "\033[0m"])
            output_file.write("\nVulnerability class:")
            output_file.write(tabulate(vuln_class_table, headers=["Vulnerability class", "Count"], tablefmt="simple"))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', nargs='?', help='Semgrep report to visualise')
    parser.add_argument('-a', '--all', action='store_true', help='Equivalent to -l -o -c -C -f')
    parser.add_argument('-l', '--languages', action='store_true', help='List impacted languages and technologies')
    parser.add_argument('-o', '--owasp', action='store_true', help='List OWASP Top 10 vulnerabilities')
    parser.add_argument('-c', '--cwe', action='store_true', help='List CWE vulnerabilities')
    parser.add_argument('-C', '--vuln-class', action='store_true',  help='Vulnerability classes as per of Semgrep')
    parser.add_argument('-f', '--files', action='store_true', help='List files with vulnerabilities')
    parser.add_argument('-t', '--test', action='store_true', help='Test installation')
    # parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')

    args = parser.parse_args()

    # print("Visu.")

    if args.test:
        print("Installation successful.")
    elif args.all:
        args.languages = True
        args.owasp = True
        args.cwe = True
        args.vuln_class = True
        args.files = True
        summarize_findings(args.file, args)
    elif args.file:
        summarize_findings(args.file, args)

if __name__ == "__main__":
    main()