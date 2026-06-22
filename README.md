# Enterprise Cloud-Native Security Audit Tool (CSPM)

A production-grade **Cloud Security Posture Management (CSPM)** engine built with Java 17, Spring Boot, and the AWS SDK v2. Automatically scans AWS infrastructure for security misconfigurations and reports violations by severity — deployed as a serverless AWS Lambda function with daily automated execution via Amazon EventBridge.

---

## Application Preview

### Local CLI Scan Dashboard
![Local Scan Dashboard](docs/screenshots/scan-dashboard.png)

### AWS Lambda Execution — Succeeded
![AWS Lambda Success](docs/screenshots/lambda-success.png)

### CloudWatch Audit Results
![AWS Lambda Audit Results](docs/screenshots/lambda-audit-result.png)

---

## Security Checks

| Check | AWS Service | Severity |
|-------|-------------|----------|
| Block Public Access not fully enabled | S3 | CRITICAL |
| Public ACL granting access to AllUsers | S3 | CRITICAL |
| SSH (port 22) open to 0.0.0.0/0 | EC2 Security Groups | HIGH |
| RDP (port 3389) open to internet | EC2 Security Groups | HIGH |
| Database ports exposed to internet | EC2 Security Groups | HIGH |
| AdministratorAccess policy attached to IAM role | IAM | CRITICAL |
| Wildcard Action:* in inline policy | IAM | HIGH |
| iam:PassRole without conditions | IAM | MEDIUM |
| Unencrypted EBS volume | EBS | MEDIUM |
| Unencrypted RDS instance | RDS | MEDIUM |
| Publicly accessible RDS instance | RDS | HIGH |

---

## Architecture
Amazon EventBridge (daily cron: 9am UTC)

↓

AWS Lambda Function

(Java 17 · ARM64 · 512MB · 5min timeout)

↓

SecurityAuditLambdaHandler

↓

CloudSecurityAuditService

↓

┌──────────────┬───────────────────┬──────────────┬────────────────────────┐

│S3BucketScanner│SecurityGroupScanner│IamRoleScanner│StorageEncryptionScanner│

└──────────────┴───────────────────┴──────────────┴────────────────────────┘

↓

AuditReport (JSON) → Amazon CloudWatch Logs
---

## Tech Stack

| Technology | Purpose |
|------------|---------|
| Java 17 | Core language |
| Spring Boot 3.2.5 | Application framework |
| AWS SDK for Java v2 | Cloud API integration |
| AWS Lambda | Serverless execution |
| Amazon EventBridge | Scheduled automation |
| Amazon CloudWatch | Logging and monitoring |
| Amazon S3 | Deployment artifact storage |
| Maven + Shade Plugin | Build and packaging |

---

## Running Locally

**Prerequisites:** Java 17, Maven, AWS CLI

```bash
git clone https://github.com/ShaunDevynB/cloud-security-audit-tool.git
cd cloud-security-audit-tool
aws configure
./mvnw spring-boot:run
```

---

## Deploying to AWS Lambda

```bash
# Build the deployment JAR
./mvnw clean package -DskipTests

# Upload to S3
aws s3 cp target/cloud-security-audit-tool-0.0.1-SNAPSHOT.jar \
  s3://your-deploy-bucket/cloud-security-audit.jar

# Update Lambda
aws lambda update-function-code \
  --function-name cloud-security-audit \
  --s3-bucket your-deploy-bucket \
  --s3-key cloud-security-audit.jar
```

---

## IAM Permissions Required

The Lambda execution role requires these read-only policies:

- `AmazonS3ReadOnlyAccess`
- `AmazonEC2ReadOnlyAccess`
- `IAMReadOnlyAccess`
- `AmazonRDSReadOnlyAccess`
- `CloudWatchLogsFullAccess`

---

## Related Projects

- [Vulnerability Assessment Lab](https://github.com/ShaunDevynB/vulnerability-assessment-lab) — AWS EC2 + Nmap
- [AI Vulnerability Scanner](https://github.com/ShaunDevynB/ai-vulnerability-scanner) — Python + Groq AI + GitHub Actions

---

## Author

**Shaun Boadi** · [github.com/ShaunDevynB](https://github.com/ShaunDevynB)
