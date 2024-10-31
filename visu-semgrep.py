import argparse
import json
from tabulate import tabulate
from collections import Counter

# Usable emojis: 👁️🧱🔗🆘🚫❌⭕✅❎🆗🆕0️⃣1️⃣2️⃣3️⃣4️⃣5️⃣6️⃣7️⃣8️⃣9️⃣🔟▶️⏹️➡️⬇️🔣🔄🔴🟠🟡🟢🟥🟧🟨🟩🔺🔻📄🧾📁🎯🤖🛠️🔧⚙️💻🚀📢🚨🔥💥☢️⚡👾🔎💡⚠️💎

def display_help():
    print("\033[1mVisu\033[36m.\033[0m 👁️  - Adrien BLAIR\n")
    print("Visualise JSON report file generated by \033[36mSemgrep\033[0m.\n")
    print("Usage: visu [\033[36margs\033[0m] <file.json>")
    print("\033[4mOptions:\033[0m")
    print("  \033[36m-h\033[0m,\033[36m --help\033[0m        Show this help message")
    print("  \033[36m-a\033[0m,\033[36m --all\033[0m         Equivalent to -l -o -c -C -f")
    print("  \033[36m-c\033[0m,\033[36m --cwe\033[0m         List CWE vulnerabilities")
    print("  \033[36m-C\033[0m,\033[36m --vuln-class\033[0m  Vulnerability classes as per of Semgrep")
    print("  \033[36m-f\033[0m,\033[36m --files\033[0m       List files with vulnerabilities")
    print("  \033[36m-l\033[0m,\033[36m --languages\033[0m   List impacted languages and technologies")
    print("  \033[36m-o\033[0m,\033[36m --owasp\033[0m       List OWASP Top 10 vulnerabilities")
    print("  \033[36m-v\033[0m,\033[36m --verbose\033[0m     Verbose mode")
    print("  \033[36m-w\033[0m,\033[36m --web\033[0m         Launch web viewer")

def summarize_findings(file_path, args):
    with open(file_path, 'r') as file:
        data = json.load(file)

    results = data.get("results", [])
    severity_map = {"ERROR": "\033[91mHigh\033[0m", "WARNING": "\033[33mMedium\033[0m", "INFO": "\033[92mLow\033[0m"}
    severity_count = Counter(severity_map[result["extra"]["severity"]] for result in results)

    all_severities = ["\033[91mHigh\033[0m", "\033[33mMedium\033[0m", "\033[92mLow\033[0m"]
    severity_table = [[sev, severity_count.get(sev, 0)] for sev in all_severities]
    severity_table.append(["\033[1mTotal\033[0m", "\033[1m" + str(sum(severity_count.values())) + "\033[0m"])

    # Severity count
    print("\n📄 \033[1mResults summary:\033[0m")
    print(tabulate(severity_table, headers=["Severity", "Count"], tablefmt="rounded_grid"))

    # Option -l : Languages used
    if args.languages:
        tech_count = Counter(
            tech
            for result in results
            for tech in result["extra"]["metadata"].get("technology", [])
        )
        tech_table = [[k, v] for k, v in tech_count.most_common()]
        tech_table.append(["\033[1mTotal\033[0m", "\033[1m" + str(sum(tech_count.values())) + "\033[0m"])
        print("\n🔣 Languages:")
        print(tabulate(tech_table, headers=["Technology", "Count"], tablefmt="rounded_outline"))

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
        print("\n🔟 OWASP Top 10:")
        print(tabulate(owasp_table, headers=["OWASP", "Count"], tablefmt="rounded_outline"))

    # Option -c : CWE vulnerabilities
    if args.cwe:
        cwe_count = Counter(
            cwe
            for result in results
            for cwe in (result["extra"]["metadata"].get("cwe", []) if isinstance(result["extra"]["metadata"].get("cwe", []), list) else [result["extra"]["metadata"].get("cwe", [])])
        )
        cwe_table = [[k, v] for k, v in cwe_count.most_common()]
        print("\n📢 CWE:")
        print(tabulate(cwe_table, headers=["CWE", "Count"], tablefmt="rounded_outline"))
        cwe2022_top25_count = sum(1 for result in results if result["extra"]["metadata"].get("cwe2022-top25", False))
        print("\n🔥 Including \033[1m" + str(cwe2022_top25_count) + "\033[0m " + "CWE top 25.")

    # Option -f : Vulnerable files
    if args.files:
        file_count = Counter(result["path"] for result in results)
        file_table = [[k, v] for k, v in file_count.most_common()]
        file_table.append(["\033[1mTotal\033[0m", "\033[1m" + str(sum(file_count.values())) + "\033[0m"])
        print("\n📁 Files with vulnerabilities:")
        print(tabulate(file_table, headers=["File", "Count"], tablefmt="rounded_outline"))

    # Option -C : Vulnerability class
    if args.vuln_class:
        vuln_class_count = Counter(
            vuln_class
            for result in results
            for vuln_class in result["extra"]["metadata"].get("vulnerability_class", [])
        )
        vuln_class_table = [[k, v] for k, v in vuln_class_count.most_common()]
        vuln_class_table.append(["\033[1mTotal\033[0m", "\033[1m" + str(sum(vuln_class_count.values())) + "\033[0m"])
        print("\n🎯 Vulnerability class:")
        print(tabulate(vuln_class_table, headers=["Vulnerability class", "Count"], tablefmt="rounded_outline"))

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('file', nargs='?', help='Semgrep report to visualise')
    parser.add_argument('-a', '--all', action='store_true', help='Equivalent to -l -o -c -C -f')
    parser.add_argument('-l', '--languages', action='store_true', help='List impacted languages and technologies')
    parser.add_argument('-o', '--owasp', action='store_true', help='List OWASP Top 10 vulnerabilities')
    parser.add_argument('-c', '--cwe', action='store_true', help='List CWE vulnerabilities')
    parser.add_argument('-C', '--vuln-class', action='store_true',  help='Vulnerability classes as per of Semgrep')
    parser.add_argument('-f', '--files', action='store_true', help='List files with vulnerabilities')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    parser.add_argument('-w', '--web', action='store_true', help='Launch web viewer')

    args = parser.parse_args()

    # print(args)

    if args.help or not args.file:
        display_help()
    elif args.web and args.file:
        print("Web viewer not implemented yet.")
    elif args.all:
        args.languages = True
        args.owasp = True
        args.cwe = True
        args.vuln_class = True
        args.files = True
        summarize_findings(args.file, args)
    else:
        summarize_findings(args.file, args)

if __name__ == "__main__":
    main()