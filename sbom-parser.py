import hashlib
import json
import sys
from typing import List, Dict, Any
import os
from datetime import datetime
from pymongo import MongoClient


def upload_report(sbom_file_path: str, sca_file_path: str):
    with open(sbom_file_path, 'r') as file:
        content = file.read()
        report = json.loads(content)
    with open(sca_file_path, 'r') as file:
        sca_report_content = file.read()
    if dbConnectionOk and report:
        try:
            project_id = os.getenv("PROJECT_ID")
            mongodb_url = os.getenv("MONGODB_URL")
            mongodb_username = os.getenv("MONGODB_USERNAME")
            mongodb_password = os.getenv("MONGODB_PASSWORD")
            #! Might need to add options based on the database type
            ############################################################################################################
            mongoDB_conncection_string = f"mongodb://{mongodb_username}:{mongodb_password}@{mongodb_url}/?authSource=visu"
            client = MongoClient(mongoDB_conncection_string)
            collection = client["visu"]["sbom"]
            report['project_id'] = int(project_id)
            report['sbom_report_number'] = collection.count_documents({"project_id": int(project_id)})
            report['date_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if sca_report_content:
                sca_reports = [json.loads(line) for line in sca_report_content.strip().split('\n')]
                if len(sca_reports) > 0:
                    for sca_report in sca_reports:
                        sca_report['severity'] = sca_report['severity'].replace("CRITICAL", "Critical").replace("HIGH", "High").replace("MEDIUM", "Medium").replace("LOW", "Low")
                        component = next((component for component in report['components'] if component['purl'] == sca_report['purl']), None)
                        if component:
                            if 'sca_findings' in component:
                                component['sca_findings'].append(sca_report)
                            else:
                                component['sca_findings'] = [sca_report]
                            component['vulnerable'] = True
            # NOTE: For debugging purposes, comment the next line to avoid uploading the report to MongoDB
            collection.insert_one(report)
            print("Report uploaded to MongoDB")
        except Exception as e:
            print(f"Failed to upload report to MongoDB: {e}")
    else:
        print("Error: MongoDB connection not available.")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python sca-parser.py <sbom_file_path> <sca_file_path>\n where <sbom_file_path> is the path to the SBOM file and <sca_file_path> is the path to the SCA file")
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

    sbom_file_path = sys.argv[1]
    sca_file_path = sys.argv[2]
    print (f"Uploading report from {sbom_file_path} and {sca_file_path}")
    upload_report(sbom_file_path, sca_file_path)