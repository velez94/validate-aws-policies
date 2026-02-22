"""Automate Ops, validate and create reports."""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from zipfile import ZipFile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from colorama import Fore


logger = logging.getLogger(__name__)


def read_policies(file_path: Path) -> Optional[str]:
    """
    Read policies from a text file and return them as a string.

    Args:
        file_path: Path object of the text file containing the policies

    Returns:
        Policy document as string, or None if file cannot be opened

    Raises:
        FileNotFoundError: If the policy file doesn't exist
    """
    logger.debug(f"Reading policy from: {file_path}")

    if not file_path.is_file():
        logger.error(f"Cannot open the file: {file_path}")
        return None

    try:
        with file_path.open("r", encoding="utf-8") as f:
            data = f.read()
        logger.debug(f"Successfully read policy: {file_path.name}")
        return data
    except FileNotFoundError:
        logger.error(f"Policy file not found: {file_path}")
        raise
    except Exception as e:
        logger.error(f"Error reading policy file {file_path}: {e}")
        raise


def validate_findings(policy: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Validate findings for a policy and return a summary of the findings.

    Args:
        policy: Policy file name
        findings: List of findings for the policy

    Returns:
        Dictionary containing filePolicy and summary of findings

    Raises:
        ValueError: If ERROR-level finding is detected
    """
    policy_name = Path(policy).stem
    summary: Dict[str, Any] = {"filePolicy": policy, "summary": []}

    if len(findings) == 0:
        logger.info(f"✅ No findings for {policy}")
        summary["summary"].append(
            {
                "policyName": policy_name,
                "issueCode": "None",
                "findingType": "None",
                "details": "No findings",
            }
        )
    else:
        logger.info(f"There are some findings for {policy_name}")
        logger.info("Findings:")

        for f in findings:
            if f["findingType"] == "ERROR":
                logger.error(f"Error finding in {policy_name}: {json.dumps(f, indent=4)}")
                raise ValueError(f"ERROR - Found problems with policy {policy_name}")

            logger.warning(f"Summary for {policy_name}")
            logger.warning(f"policyName: {policy_name}")

            if f.get("issueCode") is not None:
                logger.warning(f"⚠️ issueCode: {f['issueCode']}")

            logger.warning(f"⚠️ findingType: {f['findingType']}")
            logger.warning(f"⚠️ Details: {json.dumps(f, indent=4)}")

            # Create dict for report summary
            summary["summary"].append(
                {
                    "policyName": policy_name,
                    "issueCode": f.get("issueCode"),
                    "findingType": f["findingType"],
                    "details": f,
                }
            )

    return summary


def upload_file(file_name: Path, bucket: str, key: str = "reports", max_retries: int = 3) -> bool:
    """
    Upload a file to an S3 bucket with retry logic and exponential backoff.

    Args:
        file_name: Path to file to upload
        bucket: Bucket to upload to
        key: Object Key
        max_retries: Maximum number of retry attempts (default: 3)

    Returns:
        True if file was uploaded, else False
    """
    # Configure boto3 with adaptive retry mode
    config = Config(retries={"max_attempts": max_retries, "mode": "adaptive"})
    s3_client = boto3.client("s3", config=config)

    # Manual retry with exponential backoff for additional resilience
    for attempt in range(max_retries):
        try:
            s3_client.upload_file(str(file_name), bucket, Key=key)
            logger.info(f"Successfully uploaded {file_name.name} to s3://{bucket}/{key}")
            logger.info(f"{Fore.GREEN} ✨ The reports was uploaded{Fore.RESET}")
            return True
        except ClientError as e:
            if attempt == max_retries - 1:
                # Final attempt failed
                logger.error(f"Error uploading {file_name.name} after {max_retries} attempts: {e}")
                logger.error(f"{Fore.RED} ⚠️ Error uploading the reports{Fore.RESET}")
                return False

            # Calculate exponential backoff wait time
            wait_time = 2**attempt
            logger.warning(
                f"Upload attempt {attempt + 1}/{max_retries} failed for {file_name.name}, "
                f"retrying in {wait_time}s: {e}"
            )
            time.sleep(wait_time)

    return False


def create_zip(file_paths: List[Path]) -> Path:
    """
    Create a zip file of the reports.

    Args:
        file_paths: List of file paths to zip

    Returns:
        Path to the created zip file
    """
    d = datetime.now()
    zip_name = Path(f"reports_{d}.zip")

    logger.info("Creating zip archive.")

    with ZipFile(zip_name, "w") as zip_file:
        for file in file_paths:
            logger.info(f"{file} Zipped!!")
            zip_file.write(file)

    logger.info("✅ All files zipped successfully!")
    logger.info(f"{Fore.GREEN}✅ All files zipped successfully!{Fore.RESET}")

    return zip_name


