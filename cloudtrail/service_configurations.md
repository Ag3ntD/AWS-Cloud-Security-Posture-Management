# Service Configurations

## IAM Role

**Lambda Execution Role:** `Lambda-CloudTrail-Logging`

**Permissions (Least Privilege):**

### DynamoDB Access
- `dynamodb:PutItem` - Write findings to security-findings table
- `dynamodb:GetItem` - Read previous finding state
- **Resource:** `arn:aws:dynamodb:us-east-1:382858227278:table/security-findings`

### SQS Access
- `sqs:SendMessage` - Send alerts to queue
- **Resource:** `arn:aws:sqs:us-east-1:382858227278:cloudtrail-logging-status`

### CloudWatch Logs (Automatic)
- `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`

### CloudTrail
- `cloudtrail:ListTrails`
- `cloudtrail:DescribeTrails`
-  `cloudtrail:GetTrailStatus`
- **Resource:** "*"


## EventBridge 

### Event Pattern

```json
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["cloudtrail.amazonaws.com"],
    "eventName": [
      "StopLogging",
      "DeleteTrail",
      "UpdateTrail"
    ]
  }
}
```

## Lambda

### Set Trigger
- EventBridge (CloudWatch Events): `CloudTrail-Logging-Trigger`

### Set Environment Variables
`QUEUE_URL`
`TABLE_NAME`

### Assign IAM Role
`Lambda-CloudTrail-Logging`

## DynamoDB
### Create Table
Set Partition key `finding_id (S)`
**Reminder** Set Lambda enviroment variable `TABLE_NAME` to table name
 
