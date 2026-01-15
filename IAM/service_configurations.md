# Service Configurations - IAM PassRole Escalation Scanner

## IAM Role

**Lambda Execution Role:** `iam-passrole-scanner-lambda-role`

**Permissions (Least Privilege):**

### IAM Read-Only Access
- `iam:ListUsers` - List all IAM users in account
- `iam:ListAttachedUserPolicies` - List managed policies attached to users
- `iam:ListUserPolicies` - List inline policies for users
- `iam:GetUserPolicy` - Read inline policy documents
- `iam:GetPolicy` - Read managed policy metadata
- `iam:GetPolicyVersion` - Read managed policy documents

### DynamoDB Access
- `dynamodb:PutItem` - Write findings to security-findings table
- `dynamodb:GetItem` - Read previous finding state
- `dynamodb:Scan` - Query for resolved findings
- **Resource:** `arn:aws:dynamodb:us-east-1:382858227278:table/security-findings`

### SQS Access
- `sqs:SendMessage` - Send alerts to queue
- **Resource:** `arn:aws:sqs:us-east-1:382858227278:s3-bucket-status`

### CloudWatch Logs (Automatic)
- `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`

**No write permissions to IAM, EventBridge, or other AWS services.**

---

## EventBridge

### Scheduled Rule
```
rate(1 hour)
```

**Trigger Type:** Scheduled (time-based)

**Rationale:** IAM permissions inherit from groups and roles, making event-driven detection incomplete. Scheduled scanning ensures all permission paths are evaluated, including group memberships and policy inheritance.

**Alternative schedules:**
- `rate(6 hours)` - Less frequent for low-change environments
- `rate(30 minutes)` - More aggressive for high-security requirements

---

## Lambda

### Set Trigger
- EventBridge (CloudWatch Events): `iam-passrole-scan-schedule`

### Set Environment Variables
- `TABLE_NAME` = `security-findings`
- `QUEUE_URL` = `https://sqs.us-east-1.amazonaws.com/382858227278/s3-bucket-status`

### Assign IAM Role
`iam-passrole-scanner-lambda-role`

### Configuration
- **Runtime:** Python 3.x
- **Timeout:** 120 seconds (allows time to scan all users and their policies)
- **Memory:** 256 MB (higher memory for policy parsing)

---

## DynamoDB

### Create Table
Set Partition key `finding_id (S)`

**Sample IAM Finding:**
```json
{
  "finding_id": "iam-passrole-escalation-alice",
  "check_type": "iam-passrole-escalation",
  "resource_type": "iam-principal",
  "principal": "alice",
  "account_id": "382858227278",
  "severity": "CRITICAL",
  "status": "ACTIVE",
  "reason": "Principal can pass roles and invoke execution services, enabling privilege escalation",
  "exploit_path": ["iam:PassRole", "execution-service", "privileged-role-assumption"],
  "detected_at": "2026-01-14T22:30:00Z",
  "updated_at": "2026-01-14T22:30:00Z"
}
```

**Note:** Shared table with other security scanners - all findings stored centrally

**Reminder:** Set Lambda environment variable `TABLE_NAME` to table name

---

## SQS Queue

**Queue Name:** `s3-bucket-status`

**Note:** Centralized alert queue for all security scanners

**Alert Types:**
- `NEW_FINDING` - Privilege escalation path detected for first time
- `REOPENED_FINDING` - User regained escalation permissions after remediation
- `RESOLVED_FINDING` - User no longer has escalation path

---
