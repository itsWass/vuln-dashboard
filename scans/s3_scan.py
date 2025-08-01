import boto3
import json
from botocore.exceptions import ClientError
from dotenv import load_dotenv
import os

# Load .env variables
load_dotenv()

DUMMY_MODE = os.getenv("DUMMY_DATA", "False") == "True"

# Initialize S3 client (only used if not dummy mode)
s3_client = boto3.client(
    's3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)

def check_s3_buckets():
    # Dummy data mode
    if DUMMY_MODE:
        return [
            {
                "resource_type": "S3 Bucket",
                "resource_name": "public-bucket-demo",
                "issue": "Bucket is publicly accessible",
                "severity": "High",
                "recommendation": "Restrict bucket ACL or bucket policy"
            },
            {
                "resource_type": "S3 Bucket",
                "resource_name": "unencrypted-bucket-demo",
                "issue": "Bucket is not encrypted",
                "severity": "Medium",
                "recommendation": "Enable default encryption"
            }
        ]

    findings = []

    # Real AWS Scan
    try:
        buckets = s3_client.list_buckets()['Buckets']
    except ClientError:
        return findings

    for bucket in buckets:
        bucket_name = bucket['Name']

        # --- Check if bucket is public ---
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                if 'URI' in grant['Grantee'] and 'AllUsers' in grant['Grantee']['URI']:
                    findings.append({
                        "resource_type": "S3 Bucket",
                        "resource_name": bucket_name,
                        "issue": "Bucket is publicly accessible",
                        "severity": "High",
                        "recommendation": "Remove public ACL or restrict access"
                    })
        except ClientError:
            pass

        # --- Check encryption ---
        try:
            s3_client.get_bucket_encryption(Bucket=bucket_name)
        except ClientError:
            findings.append({
                "resource_type": "S3 Bucket",
                "resource_name": bucket_name,
                "issue": "Bucket is not encrypted",
                "severity": "Medium",
                "recommendation": "Enable default encryption"
            })

    return findings


if __name__ == "__main__":
    print(json.dumps(check_s3_buckets(), indent=2))