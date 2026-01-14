## Architecture

Event-driven CloudTrail monitoring system. When CloudTrail configuration changes occur (StopLogging, DeleteTrail, UpdateTrail), EventBridge captures these events via CloudTrail logs and triggers a Lambda function. Lambda validates the trail's logging status by querying the CloudTrail API, stores findings in DynamoDB with state tracking (ACTIVE/RESOLVED), and sends SQS alerts only on state transitions (NEW_FINDING, REOPENED_FINDING, RESOLVED_FINDING).
