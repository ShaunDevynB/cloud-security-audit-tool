# Enterprise Cloud-Native Security Audit Tool (CSPM)

A production-grade **Cloud Security Posture Management (CSPM)** engine built with Java Spring Boot and the AWS SDK v2. Automatically scans AWS infrastructure for security misconfigurations and logs violations by severity.

---

## 📷 Application Preview & Deployment Visuals

### 📊 Posture Assessment Dashboard (Local CLI)
When executed locally via the command line, the core CSPM engine directly coordinates rule checks across your S3, EC2 Security Groups, and IAM Policies, outputting a prioritized compliance summary report straight to the console:

![Local Scan Dashboard](docs/screenshots/scan-dashboard.png)

### ☁️ Serverless AWS Lambda Orchestration
The project features a compiled native AWS Lambda request handler, enabling the tool to run as a serverless microservice. This allows for automated, event-driven posture audits triggered by AWS EventBridge cron schedules or CloudTrail security alerts.

#### AWS Lambda Context Invocation
The cloud function triggers seamlessly inside the AWS environment, completing the full multi-domain resource audit within standard serverless runtime boundaries:

![AWS Lambda Success](docs/screenshots/lambda-success.png)

#### Cloud Execution Results Log
When running in the cloud, the tool pipes execution metrics and JSON-formatted vulnerability reports directly to Amazon CloudWatch logs for permanent record-keeping:

![AWS Lambda Audit Results](docs/screenshots/lambda-audit-result.png)

---

## What It Scans

| Check | Service | Severity |
|-------|---------|----------|
| Public S3 buckets (Block Public Access disabled) | S3 | CRITICAL |
| Public S3 ACLs (AllUsers / AuthenticatedUsers) | S3 | CRITICAL |
| SSH (port 22) open to 0.0.0.0/0 | EC2 Security Groups | HIGH |
| RDP (port 3389) open to internet | EC2 Security Groups | HIGH |
| Database ports exposed to internet | EC2 Security Groups | HIGH |
| AdministratorAccess policy attached to role | IAM | CRITICAL |
| Wildcard Action:* in inline policies | IAM | HIGH |
| iam:PassRole without conditions | IAM | MEDIUM |
| Unencrypted EBS volumes | EBS | MEDIUM |
| Unencrypted RDS instances | RDS | MEDIUM |
| Publicly accessible RDS instances | RDS | HIGH |

---

## Architecture
EventBridge (daily cron)

↓

AWS Lambda (Java 17, ARM64)

↓

SecurityAuditLambdaHandler

↓

CloudSecurityAuditService

↓

┌─────────────┬──────────────────┬────────────┬──────────────────────┐
│S3BucketScanner│SecurityGroupScanner│IamRoleScanner│StorageEncryptionScanner│
└─────────────┴──────────────────┴────────────┴──────────────────────┘

↓

AuditReport (JSON) → CloudWatch Logs

---

## Tech Stack
