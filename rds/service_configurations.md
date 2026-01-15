# Service Configurations

## IAM Role

**Lambda Execution Role:** `rds-scanner-lambda-role`

**Permissions (Least Privilege):**

### RDS Read-Only Access
- `rds:DescribeDBSnapshots` - List all RDS snapshots in account
- `rds:DescribeDBSnapshotAttributes` - Check snapshot sharing permissions

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

**No write permissions to RDS, EventBridge, or other AWS services.**

---

## EventBridge

### Event Pattern
```json
{
  "source": ["aws.rds"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["rds.amazonaws.com"],
    "eventName": [
      "CreateDBSnapshot",
      "ModifyDBSnapshotAttribute",
      "DeleteDBSnapshot"
    ]
  }
}
```

**Captured Events:**
- `CreateDBSnapshot` - New snapshots created (check initial permissions)
- `ModifyDBSnapshotAttribute` - Snapshot sharing permissions changed
- `DeleteDBSnapshot` - Snapshots deleted (cleanup findings)

**Detection latency:** < 5 seconds from API call to Lambda execution

---

## Lambda

### Set Trigger
- EventBridge (CloudWatch Events): `rds-snapshot-event`

### Set Environment Variables
- `TABLE_NAME` = `security-findings`
- `QUEUE_URL` = `https://sqs.us-east-1.amazonaws.com/382858227278/s3-bucket-status`

### Assign IAM Role
`rds-scanner-lambda-role`

### Configuration
- **Runtime:** Python 3.x
- **Timeout:** 60 seconds (allows time to scan multiple snapshots)
- **Memory:** 128 MB

---

## DynamoDB

### Create Table
Set Partition key `finding_id (S)`

**Sample RDS Finding:**
```json
{
  "finding_id": "rds-snapshot-public-first-snapshot",
  "check_type": "rds-snapshot-public",
  "resource_type": "rds-snapshot",
  "resource": "first-snapshot",
  "account_id": "382858227278",
  "severity": "CRITICAL",
  "status": "ACTIVE",
  "reason": "RDS snapshot is publicly accessible (shared with 'all')",
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
- `NEW_FINDING` - Public snapshot detected for first time
- `REOPENED_FINDING` - Snapshot made public again after being fixed
- `RESOLVED_FINDING` - Snapshot no longer publicly shared
