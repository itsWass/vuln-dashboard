from flask import Flask, render_template, jsonify
from scans.s3_scan import check_s3_buckets
from scans.iam_scan import check_iam_users
from scans.sg_scan import check_security_groups

app = Flask(__name__)

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/scan', methods=['GET'])
def run_scan():
    # Run all scans
    s3_findings = check_s3_buckets()
    iam_findings = check_iam_users()
    sg_findings = check_security_groups()

    findings = s3_findings + iam_findings + sg_findings

    return jsonify(findings)

if __name__ == '__main__':
    app.run(debug=True)
