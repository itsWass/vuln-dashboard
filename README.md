**Cloud Security Monitoring Dashboard**

A Flask-based web application that scans AWS cloud resources for security misconfigurations such as public S3 buckets, unencrypted storage, inactive IAM users, and open security group ports. Includes a real-time dashboard with severity filtering, search, CSV export, and loading indicators.

**Features**

**Real AWS Integration: Scans live AWS resources using Boto3 SDK
- **Detects Common Misconfigurations:**
  - Public or unencrypted S3 buckets
  - Inactive IAM users (>90 days)
  - Security Groups with open ports (e.g., SSH 22 open to 0.0.0.0/0)
- **Interactive Dashboard:**
  - Severity filtering (High/Medium/Low)
  - Search by resource name or issue
  - CSV export of filtered results
  - Loading spinner for live scans
- **Dummy Data Mode:**
  - Built-in demo mode with sample findings (no AWS account required)

**Tech Stack**
Backend: Python 3, Flash, Boto3 (AWS SDK)
Frontend: Bootstrap 5, Vanilla JS
Deployment: `.env` for credentials, runs locally or on cloud VM

**Setup Instructions**
1. Clone Repository

`git clone https://github.com/YOUR-USERNAME/vuln-dashboard.git
`

`cd vuln-dashboard
`

2. Create Virtual Environment

`python3 -m venv venv
`

`source venv/bin/activate
`

3. Install Dependencies

`pip install -r requirements.txt
`

4. Configure Environment Variables

`AWS_ACCESS_KEY_ID=your-access-key
`

`AWS_SECRET_ACCESS_KEY=your-secret-key
`

`AWS_DEFAULT_REGION=us-east-1
`

`DUMMY_DATA=False # set True to use built-in sample data
`

5. Run the Application

`python app.py
`

Visit

`http:127.0.0.1:5000
`

**Demo Modes**

- Real Mode: Scans live AWS account (requires IAM with read-only permissions for S3, IAM, EC2)
- Demo Mode: `DUMMY_DATA=True` -> Uses sample findings for portfolios or demos without AWS access

**Permissions Required**
Attach a read-only policy with:

```{
  "Action": [
    "s3:ListAllMyBuckets",
    "s3:GetBucketAcl",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketPolicy",
    "s3:GetBucketEncryption",
    "iam:ListUsers",
    "iam:GenerateCredentialReport",
    "iam:GetCredentialReport",
    "ec2:DescribeSecurityGroups"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
```
