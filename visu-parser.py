import json
import sys
from typing import List, Dict, Any
import os
from datetime import datetime
from pymongo import MongoClient

def compare_results(result1: Dict[str, Any], result2: Dict[str, Any]) -> bool:
    if 'fingerprint' in result1['extra'] and 'fingerprint' in result2['extra']:
        return result1['extra']['fingerprint'] == result2['extra']['fingerprint']
    else:
        return result1['check_id'] == result2['check_id'] and result1['path'] == result2['path'] and result1['start']['line'] == result2['start']['line']

def transform_sarif_to_report(sarif_report: Dict[str, Any]) -> Dict[str, Any]:
    rules_map = {}
    for run in sarif_report['runs']:
        for rule in run['tool']['driver']['rules']:
            rules_map[rule['id']] = rule

    results = []
    for run in sarif_report['runs']:
        for result in run['results']:
            rule = rules_map[result['ruleId']]
            cwe = [tag for tag in rule.get('properties', {}).get('tags', []) if tag.startswith('CWE')]
            owasp = [tag for tag in rule.get('properties', {}).get('tags', []) if tag.startswith('OWASP')]

            technology = result['locations'][0]['physicalLocation']['artifactLocation']['uri'].split('.')[-1].replace("yml", "yaml")
            if "key" in technology:
                technology = "key"
            elif "conf" in technology:
                technology = "config file"
            elif len(technology) > 30:
                technology = "unknown"
            technology = technology.upper()

            results.append({
                "check_id": result['ruleId'],
                "end": {
                    "col": result['locations'][0]['physicalLocation']['region'].get('endColumn'),
                    "line": result['locations'][0]['physicalLocation']['region'].get('endLine'),
                    "offset": 0
                },
                "extra": {
                    "engine_kind": "SARIF",
                    "fingerprint": result.get('partialFingerprints', {}).get('primaryLocationLineHash', result.get('fingerprints', {}).get("matchBasedId/v1", "")),
                    "first_seen": None,
                    "first_seen_report_number": 0,
                    "fix": '',
                    "is_ignored": False,
                    "lines": result['locations'][0]['physicalLocation']['region'].get('snippet', {}).get('text'),
                    "message": result['message']['text'],
                    "metadata": {
                        "category": "security",
                        "confidence": None,
                        "cwe": cwe,
                        "impact": None,
                        "likelihood": rule.get('properties', {}).get('precision'),
                        "owasp": owasp,
                        "references": [rule.get('helpUri')] if rule.get('helpUri') else [],
                        "semgrep.dev": None,
                        "shortlink": rule.get('helpUri'),
                        "source": rule.get('helpUri'),
                        "subcategory": [],
                        "technology": [technology] if technology else [],
                        "vulnerability_class": []
                    },
                    "metavars": rule.get('properties'),
                    "severity": rule['defaultConfiguration']['level'].replace("error", "High").replace("warning", "Medium").replace("note", "Low"),
                    "validation_state": None
                },
                "new": True,
                "path": result['locations'][0]['physicalLocation']['artifactLocation']['uri'],
                "start": {
                    "col": result['locations'][0]['physicalLocation']['region']['startColumn'],
                    "line": result['locations'][0]['physicalLocation']['region']['startLine'],
                    "offset": 0
                }
            })

    errors = [{
        "code": notification['id'],
        "level": notification['defaultConfiguration']['level'],
        "message": notification['fullDescription']['text'],
        "path": "",
        "spans": [],
        "type": []
    } for notification in sarif_report['runs'][0]['tool']['driver'].get('notifications', [])]

    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = {
        "date_time": date,
        "errors": errors,
        "paths": {
            "scanned": [result['path'] for result in results]
        },
        "results": results,
        "version": sarif_report['version']
    }

    return report

def handle_new_report_import(file_path: str):
    file_extension = file_path.split(".")[-1]
    if file_extension == "json":
        handle_new_json_report_import(file_path)
    elif file_extension == "sarif":
        handle_new_sarif_report_import(file_path)
    else:
        print("Unsupported file type")

def handle_new_json_report_import(file_path: str):
    with open(file_path, 'r') as file:
        content = file.read()
        json_data = json.loads(content)
        report = {
            "date_time": json_data.get('date_time', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "errors": json_data['errors'],
            "interfile_language_used": json_data.get('interfile_language_used', []),
            "paths": json_data['paths'],
            "results": json_data['results'],
            "skipped_rules": json_data.get('skipped_rules', []),
            "version": json_data['version'],
        }
        if dbConnectionOk:
            upload_report_to_mongodb(report)
        save_report(report)

def handle_new_sarif_report_import(file_path: str):
    with open(file_path, 'r') as file:
        content = file.read()
        json_data = json.loads(content)
        sarif_report = {
            "$schema": json_data['$schema'],
            "version": json_data['version'],
            "runs": json_data['runs'],
        }
        report = transform_sarif_to_report(sarif_report)
        if dbConnectionOk:
            upload_report_to_mongodb(report)
        save_report(report)

def save_report(report: Dict[str, Any]):
    with open("parsed_file.json", 'w') as file:
        json.dump(report, file, indent=4)

def process_new_report_results(report: Dict[str, Any], previous_report: Dict[str, Any]):
    print("Processing new report results")
    for result in report['results']:
        result['extra']['severity'] = result['extra']['severity'].replace("ERROR", "High").replace("WARNING", "Medium").replace("INFO", "Low")

        # Normalize CWE and OWASP tags
        if isinstance(result['extra']['metadata']['owasp'], list):
            result['extra']['metadata']['owasp'] = [owasp.replace("21-", "21 - ")
                                                    .replace("17-", "17 - ")
                                                    .replace("A1", "A01")
                                                    .replace("A2", "A02")
                                                    .replace("A3", "A03")
                                                    .replace("A4", "A04")
                                                    .replace("A5", "A05")
                                                    .replace("A6", "A06")
                                                    .replace("A7", "A07")
                                                    .replace("A8", "A08")
                                                    .replace("A9", "A09") for owasp in result['extra']['metadata']['owasp']]
        else:
            result['extra']['metadata']['owasp'] = [result['extra']['metadata']['owasp']]

        # Normalize technology tags
        if not result['extra']['metadata'].get('technology'):
            technology = result['path'].split('.')[-1].replace("yml", "yaml")
            if "key" in technology:
                technology = "key"
            elif "conf" in technology:
                technology = "config file"
            elif len(technology) > 30:
                technology = "unknown"
            result['extra']['metadata']['technology'] = [technology.upper()]

        # Add first seen date and report number
        if report.get('date_time'):
            result['extra']['first_seen'] = report['date_time']
        result['extra']['first_seen_report_number'] = report['report_number']

        # Check if the result is new or fixed
        existing_result = next((prev_result for prev_result in previous_report['report']['results'] if compare_results(prev_result, result)), None)
        result['new'] = not existing_result
        if existing_result:
            result['extra']['first_seen'] = existing_result['extra']['first_seen']
            result['extra']['first_seen_report_number'] = existing_result['extra']['first_seen_report_number']
            if existing_result['extra']['is_ignored']:
                result['extra']['is_ignored'] = True
    print("Results processed, calculating new, fixed, and ignored findings")
    # Calculate new, fixed, and ignored findings
    previous_fixed_findings = previous_report.get('fixedFindings', [])
    for finding in previous_fixed_findings:
        finding['new'] = False
    new_fixed_findings = [result for result in previous_report['report']['results'] if not next((new_result for new_result in report['results'] if compare_results(new_result, result)), None)]
    fixed_findings = previous_fixed_findings + new_fixed_findings
    report_to_upload = {
        "report": report,
        "high": len([result for result in report['results'] if result['extra']['severity'] == "High" and not result['extra']['is_ignored']]),
        "medium": len([result for result in report['results'] if result['extra']['severity'] == "Medium" and not result['extra']['is_ignored']]),
        "low": len([result for result in report['results'] if result['extra']['severity'] == "Low" and not result['extra']['is_ignored']]),
        "fixed": len(fixed_findings),
        "ignored": len([result for result in report['results'] if result['extra']['is_ignored']]),
        "fixedFindings": fixed_findings,
    }

    return report_to_upload

def upload_report_to_mongodb(report: Dict[str, Any]):
    try:
        project_id = os.getenv("PROJECT_ID")
        mongodb_url = os.getenv("MONGODB_URL")
        mongodb_username = os.getenv("MONGODB_USERNAME")
        mongodb_password = os.getenv("MONGODB_PASSWORD")
        mongoDB_conncection_string = f"mongodb://{mongodb_username}:{mongodb_password}@{mongodb_url}/?authSource=visu"
        client = MongoClient(mongoDB_conncection_string)
        collection = client["visu"]["reports"]
        report['project_id'] = int(project_id)
        report['report_number'] = collection.count_documents({"report.project_id": int(project_id)})
        try:
            previous_report = collection.find_one({"report.project_id": int(project_id), "report.report_number": report['report_number'] - 1}, {"_id": 0})
            if previous_report["report"]["report_number"] != report['report_number'] - 1:
                raise Exception("Previous report not found")
        except Exception as e:
            print(f"Failed to get previous report from MongoDB: {e}")
            sys.exit(1)
        report_to_upload = process_new_report_results(report, previous_report)
        collection.insert_one(report_to_upload)
        print("Report uploaded to MongoDB")
    except Exception as e:
        print(f"Failed to upload report to MongoDB: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python visu-parser.py <file_path>\n where <file_path> is the path to the report file.")
        sys.exit(1)
    try:
        project_id = os.getenv("PROJECT_ID")
        mongodb_url = os.getenv("MONGODB_URL")
        mongodb_username = os.getenv("MONGODB_USERNAME")
        mongodb_password = os.getenv("MONGODB_PASSWORD")
    except Exception as e:
        print(f"Failed to get environment variables: {e}")
        sys.exit(1)
    if not project_id or not mongodb_url or not mongodb_username or not mongodb_password:
        print("Unable to find one of the following variables PROJECT_ID, MONGODBURL, MONGODB_USERNAME, MONGODB_PASSWORD")
        print("The parser will only save the parsed report as a local file.")
        print("Environment variables should be set as follows:")
        print("PROJECT_ID: <project_id> (number)")
        print("MONGODB_URL: url.example.com:27017")
        print("MONGODB_USERNAME: <username>")
        print("MONGODB_PASSWORD: <password>")
        dbConnectionOk = False
    else:
        # Test mongoDB connection
        mongoDB_conncection_string = f"mongodb://{mongodb_username}:{mongodb_password}@{mongodb_url}/?authSource=visu"
        client = MongoClient(mongoDB_conncection_string)
        # Connects to the "visu" database and try to get one item from the "projects" collection
        try:
            db = client["visu"]
            collection = db["projects"]
            testId = collection.find_one({"id": int(project_id)}, {"_id": 0})
            if not testId.get("id") == int(project_id):
                print(f"Project with id {project_id} not found in MongoDB")
                sys.exit(1)
            dbConnectionOk = True
        except Exception as e:
            print(f"Failed to connect to MongoDB: {e}")
            sys.exit(1)

    file_path = sys.argv[1]
    handle_new_report_import(file_path)