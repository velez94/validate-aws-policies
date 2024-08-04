"""Automate Ops, validate and create reports."""
import json
import logging
from datetime import datetime
from zipfile import ZipFile

import boto3
import os
import pdfkit
from botocore.exceptions import ClientError
from colorama import Fore
from json2html import json2html


def read_policies(file_path):
    """
    Read policies from a text file and return them as a string.

    :param file_path: file path of the text file containing the policies
    :return:
    """
    # check if file is present
    print(file_path)
    if os.path.isfile(file_path):
        # open text file in read mode
        text_file = open(file_path, "r")

        # read whole file to a string
        data = text_file.read()

        # close file
        text_file.close()

        print(data)
        return data
    else:
        print("Cannot open the file")
        return None


def validate_findings(policy, findings):
    """
    Validate findings for a policy and return a summary of the findings.

    :param policy: policy file name
    :param findings: findings for the policy
    :return:
    """
    policy_name = policy.replace(".json", "")
    summary = {"filePolicy": policy, "summary": []}
    if len(findings) == 0:
        logging.info(f"✅ No findings for {policy}")
        summary["summary"].append(
            {
                "policyName": policy_name,
                "issueCode": "None",
                "findingType": "None",
                "details": "No findings",
            }
        )
    else:
        logging.info(f"There are some findings for {policy_name}")
        print("Findings: \n")
        for f in findings:
            if f["findingType"] == "ERROR":
                print(Fore.RED + "Error: " + Fore.RESET)
                print(json.dumps(f, indent=4))
                raise BaseException("ERROR- Find Some Problems with policy")

            print(Fore.YELLOW + "Summary" + Fore.RESET)
            print(Fore.YELLOW + "policyName: " + policy_name + Fore.RESET)
            if f["issueCode"] is not None:
                print(Fore.GREEN + "⚠️ issueCode: " + f["issueCode"] + Fore.RESET)
            print(Fore.GREEN + "⚠️ findingType: " + f["findingType"] + Fore.RESET)
            print(Fore.YELLOW + "⚠️ Details" + Fore.RESET)
            print(json.dumps(f, indent=4))
            print("\n")
            # Create dict for write in pdf file
            summary["summary"].append(
                {
                    "policyName": policy_name,
                    "issueCode": f["issueCode"],
                    "findingType": f["findingType"],
                    "details": f,
                }
            )

        print("\n")
    return summary


def upload_file(file_name, bucket, key="reports"):
    """
    Upload a file to an S3 bucket.

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param key: Object Key
    :return: True if file was uploaded, else False
    """
    # Upload the file
    s3_client = boto3.client("s3")
    try:
        response = s3_client.upload_file(file_name, bucket, Key=key)
        logging.info(response)
    except ClientError as e:
        logging.error(e)
        return False
    return True


def create_zip(file_paths: list):
    """
    Create a zip file of the reports.

    :param file_paths: list of file paths to zip
    :return:

    """
    d = datetime.now()
    zip_name = f"reports_{d}.zip"
    logging.info("Creating zip mood.")
    # writing mood to a zipfile
    with ZipFile(zip_name, "w") as zip:
        # writing each file one by one
        for file in file_paths:
            logging.info(f"{file} Zipped!!")
            zip.write(file)
    logging.info("✅ All mood zipped successfully!")
    print(Fore.GREEN + "✅ All mood zipped successfully!" + Fore.RESET)

    return zip_name


def create_report(report, create_zip_files=False, create_pdf=False):
    """
    Create a report of the findings.

    :param create_pdf: create a pdf report
    :param report:  to create
    :param create_zip_files:  a zip report
    :return:
    """
    date = datetime.today()
    # initializing variables with values
    file_name = f"AccessAnalyzerReport_{date}"
    logging.info("Creating reports ...")
    body = """
        <html>
        <style>
      .tbl { border-collapse: collapse; width:300px; }
      .tbl th, .tbl td { padding: 5px; border: solid 1px #777; }
      .tbl th { background-color: #00ff0080; }
      .tbl-separate { border-collapse: separate; border-spacing: 5px;}

          .fl-table {
            border-radius: 5px;
            font-size: 12px;
            font-weight: normal;
            border: none;
            border-collapse: collapse;
            width: 100%;
            max-width: 100%;
            white-space: nowrap;
            background-color: white;

        }

        .fl-table td, .fl-table th {
            text-align: left;
            padding: 8px;
            border: solid 1px #777;
        }

        .fl-table td {
            border-right: 1px solid #f8f8f8;
            font-size: 14px;
        }

        .fl-table thead th {
            color: #ffffff;
            background: #4FC3D8;
        }


        .fl-table thead th:nth-child(odd) {
            color: #ffffff;
            background: #324960;
        }

        .fl-table tr:nth-child(even) {
            background: #F8F8FA;
        }

        </style>

          <h1 style="font-size:100px; color:black; margin:10px;">Validate AWS Policies Report</h1>

        <p style="font-size:30px; color: black;"><em>Access Analyzer Report for Permissions Set</em></p>

          </html>
        """

    with open(f"{file_name}.html", "w") as file:
        file.write(body)
        logging.info("Creating HTML Report...")
        content = json2html.convert(
            json=report, table_attributes='id="report-table" class="fl-table"'
        )
        print(content, file=file)
        files_paths = [f"{file_name}.html"]

    if create_pdf:
        # Create pdf file
        options = {
            "page-size": "A0",
            "margin-top": "0.7in",
            "margin-right": "0.7in",
            "margin-bottom": "0.7in",
            "margin-left": "0.7in",
            "encoding": "UTF-8",
            "orientation": "Landscape",
        }
        logging.info("Creating PDF Report...")
        pdfkit.from_file(
            f"{file_name}.html",
            f"{file_name}.pdf",
            options=options,
        )
        files_paths.append(f"{file_name}.pdf")
    if create_zip_files:
        zip_name = create_zip(
            file_paths=files_paths,
        )
        return [zip_name]
    else:
        return files_paths
