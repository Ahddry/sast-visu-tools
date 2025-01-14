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
                    "lines": result['locations'][0]['physicalLocation']['region'].get('snippet', {}).get('text'),
                    "message": result['message']['text']
                },
                "first_seen": None,
                "first_seen_report_number": 0,
                "fix": '',
                "is_ignored": False,
                "metadata": {
                    "confidence": None,
                    "cwe": cwe,
                    "impact": None,
                    "likelihood": rule.get('properties', {}).get('precision'),
                    "owasp": owasp,
                    "references": [rule.get('helpUri')] if rule.get('helpUri') else [],
                    "shortlink": rule.get('helpUri'),
                    "source": rule.get('helpUri'),
                    "language": [technology] if technology else [],
                    "vulnerability_class": []
                },
                "name": rule.get('name', result['ruleId']),
                "new": True,
                "path": result['locations'][0]['physicalLocation']['artifactLocation']['uri'],
                "severity": rule['defaultConfiguration']['level'].replace("error", "High").replace("warning", "Medium").replace("note", "Low"),
                "start": {
                    "col": result['locations'][0]['physicalLocation']['region']['startColumn'],
                    "line": result['locations'][0]['physicalLocation']['region']['startLine'],
                    "offset": 0
                },
                "state": "To qualify"
            })

    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = {
        "date_time": date,
        "paths": {
            "scanned": list({result['path'] for result in results})
        },
        "results": results,
        "version": sarif_report['version'],
        "high": len([result for result in results if result['severity'] == "High" and not result['is_ignored']]),
        "medium": len([result for result in results if result['severity'] == "Medium" and not result['is_ignored']]),
        "low": len([result for result in results if result['severity'] == "Low" and not result['is_ignored']]),
        "fixed": 0,
        "ignored": len([result for result in results if result['is_ignored']]),
        "fixedFindings": [],
    }

    return report

def transform_json_to_report(json_report: Dict[str, Any]) -> Dict[str, Any]:
    results = []
    for result in json_report['results']:
        results.append({
            "check_id": result.get('check_id', ""),
            "end": result['end'],
            "extra": {
                "engine_kind": result['extra']['engine_kind'],
                "fingerprint": result['extra']['fingerprint'],
                "lines": result['extra']['lines'],
                "message": result['extra']['message'],
            },
            "first_seen": json_report.get('date_time'),
            "first_seen_report_number": 0,
            "is_ignored": result['extra'].get('is_ignored', False),
            "metadata": {
                "confidence": result['extra']['metadata'].get('confidence'),
                "cwe": result['extra']['metadata'].get('cwe', []),
                "impact": result['extra']['metadata'].get('impact'),
                "likelihood": result['extra']['metadata'].get('likelihood'),
                "owasp": result['extra']['metadata'].get('owasp', []),
                "references": result['extra']['metadata'].get('references', []),
                "shortlink": result['extra']['metadata'].get('shortlink', ""),
                "source": result['extra']['metadata'].get('source', ""),
                "language": result['extra']['metadata'].get('technology', []),
                "vulnerability_class": result['extra']['metadata'].get('vulnerability_class', []),
            },
            "name": result.get('check_id', ""),
            "new": True,
            "path": result.get('path', ""),
            "severity": result['extra'].get('severity', ""),
            "start": result.get('start'),
            "state": "To qualify",
        })

    report = {
        "date_time": json_report['date_time'],
        "paths": json_report['paths'],
        "results": results,
        "skipped_rules": json_report.get('skipped_rules', []),
        "version": json_report['version'],
        "high": len([result for result in results if result['severity'] == "High" and not result['is_ignored']]),
        "medium": len([result for result in results if result['severity'] == "Medium" and not result['is_ignored']]),
        "low": len([result for result in results if result['severity'] == "Low" and not result['is_ignored']]),
        "fixed": 0,
        "ignored": len([result for result in results if result['is_ignored']]),
        "fixedFindings": [],
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
        jsonReport = {
            "date_time": json_data.get('date_time', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "paths": json_data['paths'],
            "results": json_data['results'],
            "skipped_rules": json_data.get('skipped_rules', []),
            "version": json_data['version'],
        }
        report = transform_json_to_report(jsonReport)
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
        result['severity'] = result['severity'].replace("ERROR", "High").replace("WARNING", "Medium").replace("INFO", "Low")

        # Normalize CWE and OWASP tags
        if isinstance(result['metadata']['owasp'], list):
            result['metadata']['owasp'] = [owasp.replace("21-", "21 - ")
                                                    .replace("17-", "17 - ")
                                                    .replace("A1", "A01")
                                                    .replace("A2", "A02")
                                                    .replace("A3", "A03")
                                                    .replace("A4", "A04")
                                                    .replace("A5", "A05")
                                                    .replace("A6", "A06")
                                                    .replace("A7", "A07")
                                                    .replace("A8", "A08")
                                                    .replace("A9", "A09") for owasp in result['metadata']['owasp']]
        else:
            result['metadata']['owasp'] = [result['metadata']['owasp']]

        # Normalize language tags
        if not result['metadata'].get('language'):
            language = result['path'].split('.')[-1].replace("yml", "yaml")
            if "key" in language:
                language = "key"
            elif "conf" in language:
                language = "config file"
            elif len(language) > 30:
                language = "unknown"
            result['metadata']['language'] = [language.upper()]

        # Add first seen date and report number
        if report.get('date_time'):
            result['first_seen'] = report['date_time']
        result['first_seen_report_number'] = report['report_number']
        # Check if the result is new or fixed
        existing_result = next((prev_result for prev_result in previous_report['results'] if compare_results(prev_result, result)), None)
        result['new'] = not existing_result
        if existing_result:
            if existing_result['first_seen']:
                result['first_seen'] = existing_result['first_seen']
            result['first_seen_report_number'] = existing_result.get('first_seen_report_number', report['report_number'] - 1)
            if existing_result['is_ignored']:
                result['is_ignored'] = True
            if existing_result['state']:
                result['state'] = existing_result['state']
            else:
                result['state'] = "To qualify"
            if existing_result['previous_state']:
                result['previous_state'] = existing_result['previous_state']
            if existing_result['comments']:
                result['comments'] = existing_result['comments']
    print("Results processed, calculating new, fixed, and ignored findings")
    # Calculate new, fixed, and ignored findings
    previous_fixed_findings = previous_report.get('fixedFindings', [])
    new_fixed_findings = [result for result in previous_report['results'] if not next((new_result for new_result in report['results'] if compare_results(new_result, result)), None)]
    for finding in new_fixed_findings:
        finding['new'] = False
        finding["state"] = "Fixed on " + report['date_time'] + " in report " + str(report['report_number'])
    fixed_findings = previous_fixed_findings + new_fixed_findings
    report_to_upload = {
        "date_time": report['date_time'],
        "paths": report['paths'],
        "project_id": report['project_id'],
        "results": report['results'],
        "version": report['version'],
        "high": len([result for result in report['results'] if result['severity'] == "High" and not result['is_ignored']]),
        "medium": len([result for result in report['results'] if result['severity'] == "Medium" and not result['is_ignored']]),
        "low": len([result for result in report['results'] if result['severity'] == "Low" and not result['is_ignored']]),
        "fixed": len(fixed_findings),
        "ignored": len([result for result in report['results'] if result['is_ignored']]),
        "fixedFindings": fixed_findings,
        "report_number": report['report_number'],
        "version": report['version']
    }

    return report_to_upload

def upload_report_to_mongodb(report: Dict[str, Any]):
    try:
        project_id = os.getenv("PROJECT_ID")
        mongodb_url = os.getenv("MONGODB_URL")
        mongodb_username = os.getenv("MONGODB_USERNAME")
        mongodb_password = os.getenv("MONGODB_PASSWORD")
        #! Might need to add options based on the database type
        ############################################################################################################
        mongoDB_conncection_string = f"mongodb://{mongodb_username}:{mongodb_password}@{mongodb_url}/?authSource=visu"
        client = MongoClient(mongoDB_conncection_string)
        collection = client["visu"]["reports"]
        report['project_id'] = int(project_id)
        report['report_number'] = collection.count_documents({"project_id": int(project_id)})
        try:
            previous_report = collection.find_one({"project_id": int(project_id), "report_number": report['report_number'] - 1}, {"_id": 0})
            if previous_report["report_number"] != report['report_number'] - 1:
                raise Exception("Previous report not found")
        except Exception as e:
            print(f"Failed to get previous report from MongoDB: {e}")
            sys.exit(1)
        report_to_upload = process_new_report_results(report, previous_report)
        # NOTE: For debugging purposes, comment the next line to avoid uploading the report to MongoDB
        collection.insert_one(report_to_upload)
        print("Report uploaded to MongoDB")
        try:
            project = client["visu"]["projects"].find_one({"id": int(project_id)}, {"_id": 0})
            project['reports'].append({
                "high": report_to_upload['high'],
                "medium": report_to_upload['medium'],
                "low": report_to_upload['low'],
                "fixed": report_to_upload['fixed'],
                "ignored": report_to_upload['ignored'],
                "report_number": report_to_upload['report_number']
            })
            client["visu"]["projects"].update_one({"id": int(project_id)}, {"$set": {"reports": project['reports']}})
            print("Project data updated in MongoDB")
        except Exception as e:
            print(f"Failed to update project data in MongoDB: {e}")
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