# Service Configurations

## IAM Role

**Lambda Execution Role:** `security-group-scanner-lambda-role`

**Permissions (Least Privilege):**

### EC2 Read-Only Access
- `ec2:DescribeSecurityGroups` - List and describe security groups in account

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

**No write permissions to EC2, EventBridge, or other AWS services.**

---

## EventBridge

### Event Pattern
```json
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": [
      "AuthorizeSecurityGroupIngress",
      "RevokeSecurityGroupIngress",
      "CreateSecurityGroup",
      "DeleteSecurityGroup"
    ]
  }
}
```

**Captured Events:**
- `AuthorizeSecurityGroupIngress` - New ingress rules added (check for 0.0.0.0/0)
- `RevokeSecurityGroupIngress` - Ingress rules removed (check for resolved findings)
- `CreateSecurityGroup` - New security groups created (check initial rules)
- `DeleteSecurityGroup` - Security groups deleted (cleanup findings)

**Detection latency:** < 5 seconds from API call to Lambda execution

---

## Lambda

### Set Trigger
- EventBridge (CloudWatch Events): `security-group-event`

### Set Environment Variables
- `TABLE_NAME` = `security-findings`
- `QUEUE_URL` = `https://sqs.us-east-1.amazonaws.com/382858227278/s3-bucket-status`

### Assign IAM Role
`security-group-scanner-lambda-role`

### Configuration
- **Runtime:** Python 3.x
- **Timeout:** 60 seconds (allows time to scan security group rules)
- **Memory:** 128 MB

---

## DynamoDB

### Create Table
Set Partition key `finding_id (S)`

**Sample Security Group Finding:**
```json
{
  "finding_id": "security-group-public-sg-12345678-tcp-22",
  "check_type": "security-group-public",
  "resource_type": "security-group",
  "resource": "web-server-sg (sg-12345678)",
  "account_id": "382858227278",
  "severity": "HIGH",
  "status": "ACTIVE",
  "reason": "Security group allows public access (0.0.0.0/0) on tcp/22",
  "detected_at": "2026-01-14T22:30:00Z",
  "updated_at": "2026-01-14T22:30:00Z"
}
```

**Severity Mapping:**
- **CRITICAL:** All ports open (-1)
- **HIGH:** SSH (22), RDP (3389), databases (3306, 5432, 1433, 27017, 6379)
- **MEDIUM:** HTTP (80), HTTPS (443)
- **LOW:** Other ports

**Note:** Shared table with other security scanners - all findings stored centrally

**Reminder:** Set Lambda environment variable `TABLE_NAME` to table name

---

## SQS Queue

**Queue Name:** `s3-bucket-status`

**Note:** Centralized alert queue for all security scanners

**Alert Types:**
- `NEW_FINDING` - Public security group rule detected for first time
- `REOPENED_FINDING` - Public rule re-added after being removed
- `RESOLVED_FINDING` - Public rule removed from security group
