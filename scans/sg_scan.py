import boto3
from dotenv import load_dotenv
import os
import json

# Load .env
load_dotenv()
DUMMY_MODE = os.getenv("DUMMY_DATA", "False") == "True"

# Initialize EC2 client
ec2_client = boto3.client(
    'ec2',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_DEFAULT_REGION')
)

def check_security_groups():
    # Dummy mode
    if DUMMY_MODE:
        return [
            {
                "resource_type": "Security Group",
                "resource_name": "sg-1234567890",
                "issue": "Port 22 open to the world (0.0.0.0/0)",
                "severity": "High",
                "recommendation": "Restrict SSH access to specific IPs"
            },
            {
                "resource_type": "Security Group",
                "resource_name": "sg-9876543210",
                "issue": "Port 80 open to the world (0.0.0.0/0)",
                "severity": "Medium",
                "recommendation": "Limit HTTP exposure or use WAF"
            }
        ]

    findings = []

    # Describe security groups
    response = ec2_client.describe_security_groups()

    for sg in response['SecurityGroups']:
        sg_id = sg['GroupId']
        group_name = sg.get('GroupName', sg_id)

        for perm in sg['IpPermissions']:
            port = perm.get('FromPort')
            for ip_range in perm.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    # Determine severity
                    if port in [22, 3389]:
                        severity = "High"
                    elif port in [80, 443]:
                        severity = "Medium"
                    else:
                        severity = "Low"

                    findings.append({
                        "resource_type": "Security Group",
                        "resource_name": group_name,
                        "issue": f"Port {port} open to the world (0.0.0.0/0)",
                        "severity": severity,
                        "recommendation": "Restrict to specific IPs or remove rule"
                    })

    return findings


if __name__ == "__main__":
    print(json.dumps(check_security_groups(), indent=2))
