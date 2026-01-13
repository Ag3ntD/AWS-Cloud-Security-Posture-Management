## Architecture

The scanner uses event driven architecture triggered by CloudTrail S3 API events(PutBucketPolicy, DeleteBucketPolicy, PutPublicAccessBlock, PutBucketAcl, and CreateBucket). EventBridge matches these evenets and invokes a Lambda function that checks the modified S3 bucket for three things: bucket policy, BPA, and ACL permissions. Lambda stores normalized findings in DynamoDB with state tracking(ACTIVE/RESOLVED). When a findings states changes Lambda sends an alert to SQS.
