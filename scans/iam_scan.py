import boto3
import csv
import io
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import json

# Load .env
load_dotenv()
DUMMY_MODE = os.getenv("DUMMY_DATA", "False") == "True"

# Initialize IAM client
iam_client = boto3.client(
    'iam',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)

def check_iam_users():
    # Dummy mode
    if DUMMY_MODE:
        return [
            {
                "resource_type": "IAM User",
                "resource_name": "inactive-user-demo",
                "issue": "User has not logged in or used keys in 120 days",
                "severity": "Medium",
                "recommendation": "Disable or delete inactive IAM users"
            }
        ]

    findings = []

    # Generate and retrieve credential report
    iam_client.generate_credential_report()
    report = iam_client.get_credential_report()
    report_content = report['Content']

    # Parse CSV content
    csv_data = report_content.decode('utf-8')
    reader = csv.DictReader(io.StringIO(csv_data))

    # Check inactivity > 90 days
    cutoff_date = datetime.utcnow() - timedelta(days=90)

    for row in reader:
        user = row['user']
        # Skip root account
        if row['user'] == '<root_account>':
            continue

        # Parse last used fields
        last_login = row['password_last_used']
        access_key_1 = row['access_key_1_last_used_date']
        access_key_2 = row['access_key_2_last_used_date']

        # Check if inactive
        inactive = True
        for date_str in [last_login, access_key_1, access_key_2]:
            if date_str not in ("N/A", "no_information"):
                try:
                    date_obj = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S+00:00")
                    if date_obj > cutoff_date:
                        inactive = False
                except ValueError:
                    pass  # ignore bad dates

        if inactive:
            findings.append({
                "resource_type": "IAM User",
                "resource_name": user,
                "issue": "User inactive > 90 days",
                "severity": "Medium",
                "recommendation": "Disable or delete inactive IAM users"
            })

    return findings


if __name__ == "__main__":
    print(json.dumps(check_iam_users(), indent=2))
