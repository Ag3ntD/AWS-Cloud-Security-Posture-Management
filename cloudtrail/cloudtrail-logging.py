import json
import boto3
from datetime import datetime
import os

cloudtrail = boto3.client("cloudtrail")
dynamodb = boto3.resource("dynamodb")
sqs = boto3.client('sqs')

TABLE_NAME = os.environ["TABLE_NAME"]       
QUEUE_URL = os.environ["QUEUE_URL"]

table = dynamodb.Table(TABLE_NAME)

def send_alert(finding, state_transition, previous_status):
    """Send SQS alert for finding state changes."""
    alert_types = {
        (None, "ACTIVE"): "NEW_FINDING",
        ("RESOLVED", "ACTIVE"): "REOPENED_FINDING",
        ("ACTIVE", "RESOLVED"): "RESOLVED_FINDING"
    }
    
    alert_type = alert_types.get((previous_status, finding["status"]))
    
    if not alert_type:
        return  
    
    message = {
        "alert_type": alert_type,
        "finding_id": finding["finding_id"],
        "resource": finding["resource"],
        "severity": finding["severity"],
        "status": finding["status"],
        "reason": finding["reason"],
        "account_id": finding["account_id"],
        "timestamp": datetime.now().isoformat(),
        "previous_status": previous_status,
        "remediation": "Enable logging on Trail"
    }
    
    sqs.send_message(
        QueueUrl=QUEUE_URL,
        MessageBody=json.dumps(message, indent=2)
    )
    print(f"[ALERT] {alert_type}: {finding['finding_id']}")

def lambda_handler(event, context):
    response = cloudtrail.list_trails()
    account_id = context.invoked_function_arn.split(":")[4]
    
    for trail in response["Trails"]:
        trail_name = trail['Name']
        status_response = cloudtrail.get_trail_status(Name=trail_name)
        finding_id = f"cloudtrail-not-logging-{trail_name}"
        
        # Get previous finding
        try:
            previous_finding = table.get_item(Key={"finding_id": finding_id}).get("Item")
        except:
            previous_finding = None
        
        previous_status = previous_finding.get("status") if previous_finding else None
        is_logging = status_response.get("IsLogging", False)
        
        if not is_logging:
            # Trail NOT logging - ACTIVE finding
            finding = {
                "finding_id": finding_id,
                "check_type": "cloudtrail-not-logging",
                "resource_type": "cloudtrail",
                "resource": trail_name,
                "account_id": account_id,
                "severity": "HIGH",
                "status": "ACTIVE",
                "reason": "CloudTrail logging is disabled",
                "detected_at": previous_finding.get("detected_at", datetime.now().isoformat()) if previous_finding else datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat()
            }
            
            table.put_item(Item=finding)
            print(f"[ACTIVE] {trail_name} is not logging")
            
            # Alert if state changed
            if previous_status != "ACTIVE":
                send_alert(finding, "state changed", previous_status)
        
        else:
            # Trail IS logging
            if previous_status == "ACTIVE":
                # Mark as RESOLVED
                finding = {
                    "finding_id": finding_id,
                    "check_type": "cloudtrail-not-logging",
                    "resource_type": "cloudtrail",
                    "resource": trail_name,
                    "account_id": account_id,
                    "severity": "HIGH",
                    "status": "RESOLVED",
                    "reason": "CloudTrail logging is disabled",
                    "detected_at": previous_finding.get("detected_at", datetime.now().isoformat()),
                    "resolved_at": datetime.now().isoformat(),
                    "updated_at": datetime.now().isoformat()
                }
                
                table.put_item(Item=finding)
                send_alert(finding, "state changed", previous_status)
                print(f"[RESOLVED] {trail_name} is now logging")
            else:
                print(f"[COMPLIANT] {trail_name} is logging")

    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Scan complete'})
    }
