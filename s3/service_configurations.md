# Service Configurations

## IAM Role

**Lambda Execution Role:** `s3-scanner-lambda-role`

**Permissions (Least Privilege):**

### S3 Read-Only Access
- `s3:ListAllMyBuckets` - List all buckets in account
- `s3:GetBucketPolicy` - Read bucket policies
- `s3:GetBucketPolicyStatus` - Check if policy allows public access
- `s3:GetBucketAcl` - Read bucket ACLs
- `s3:GetPublicAccessBlock` - Check Block Public Access settings

### DynamoDB Access
- `dynamodb:PutItem` - Write findings to security-findings table
- `dynamodb:GetItem` - Read previous finding state
- **Resource:** `arn:aws:dynamodb:us-east-1:382858227278:table/security-findings`

### SQS Access
- `sqs:SendMessage` - Send alerts to queue
- **Resource:** `arn:aws:sqs:us-east-1:382858227278:s3-bucket-status`

### CloudWatch Logs (Automatic)
- `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`

**No write permissions to S3, EventBridge, or other AWS services.**


## EventBridge 

### Event Pattern

```json
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["s3.amazonaws.com"],
    "eventName": [
      "CreateBucket",
      "PutBucketPolicy",
      "DeleteBucketPolicy",
      "PutPublicAccessBlock",
      "DeletePublicAccessBlock",
      "PutBucketAcl"
    ]
  }
}
```

## Lambda

### Set Trigger
- EventBridge (CloudWatch Events): `s3-bucket-event`

### Set Enviroment Variables
`QUEUE_URL`
`TABLE_NAME`

### Assign IAM Role
`s3-scanner-lambda-role`

## DynamoDB
### Create Table
Set Partition key `finding_id (S)`
**Reminder** Set Lambda enviroment variable `TABLE_NAME` to table name
 
