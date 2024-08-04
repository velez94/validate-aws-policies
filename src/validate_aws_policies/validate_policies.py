"""Run menu."""
import argparse
import json
import logging
from datetime import datetime
from colorama import Fore
import argcomplete
import boto3
import os

from .iam_access_analyzer.iam_access_analyzer import validate_policies
from .ops.ops import create_report, upload_file
from .version import __version__

logging.basicConfig(level=logging.FATAL)
dirname = os.path.dirname(__file__)


def main() -> int:
    """
    Validate SCP policies using AWS Access Analyzer API and create reports.

    :return:
    """
    bucket_name = None
    logging.info(f"Compliance date:{datetime.now()}")

    # Initialize parser
    parser = argparse.ArgumentParser()

    # Adding optional argument
    parser.add_argument(
        "-c", "--ci", help="Run into pipeline if it's present", action="store_true"
    )
    parser.add_argument("-u", "--upload_report", help="Upload reports to s3 bucket")
    parser.add_argument(
        "-b",
        "--bucket_name",
        help="Use this flag for setting the bucket tool if --upload_report is present.",
        action="store_true",
    )
    parser.add_argument(
        "-d",
        "--directory_policies_path",
        help="Path where Policies are defined in json format",

    )
    parser.add_argument(
        "-p", "--profile", help="AWS cli profile for Access Analyzer Api", default=None
    )
    parser.add_argument(
        "-z",
        "--zip_reports",
        help="Set in True if you want to create a zip file for reports",
        action="store_true",
    )

    parser.add_argument(
        "-cp",
        "--create_pdf_reports",
        help="Set it  if you want to create a pdf report, this need wkhtmltopdf file for reports",
        action="store_true",
    )
    # create version argument
    parser.add_argument("-v", "--version", help="Print the package version", action="store_true")

    # Read arguments from command line
    args = parser.parse_args()
    # Add autocomplete
    argcomplete.autocomplete(parser)
    logging.info(f"The arguments are {args}")

    try:
        if args.version:
            print(f"Version: {__version__}")
            return 0
        if args.ci:
            logging.info("Continuous integration mood On")

        if args.upload_report:
            logging.info("Upload report to AWS s3 mood On")

        if args.bucket_name:
            bucket_name = args.bucket_name

        policies_path = args.directory_policies_path
        logging.info(f"Policies path is: {policies_path}")

        if args.profile:
            profile = args.profile
            if profile is not None:
                boto3.setup_default_session(profile_name=profile)
            logging.info(f"Profile is: {profile}")

        if args.zip_reports:
            create_zip_files = True
        else:
            create_zip_files = False

        list_policies = os.listdir(policies_path)

        if args.create_pdf_reports:
            create_pdf_reports = True
        else:
            create_pdf_reports = False

        logging.info(list_policies)

        report = validate_policies(
            list_policies=list_policies, policies_path=policies_path
        )
        print(f"{Fore.GREEN}🧐 Results: {Fore.RESET}")
        print(json.dumps(report, indent=4))

        report = json.dumps(report, indent=4)
        reports = create_report(
            report=report,
            create_zip_files=create_zip_files,
            create_pdf=create_pdf_reports,
        )

        if args.upload_report and bucket_name is not None:
            date = datetime.today().strftime("%Y/%m/%d")
            for r in reports:
                upload_file(
                    file_name=r, bucket=bucket_name, key=f"AccessAnalyzer/{date}/{r}"
                )

    except Exception as err:
        # output error, and return with an error code
        print(str(err))
        return 1
    return 0


if __name__ == "__main__":
    main()
