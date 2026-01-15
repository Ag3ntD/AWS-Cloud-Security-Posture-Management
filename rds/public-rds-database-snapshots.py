import json
import boto3
from datetime import datetime
import os

rds = boto3.client("rds")
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
        "remediation": "Remove 'all' from RDS snapshot restore permissions"
    }
    
    sqs.send_message(
        QueueUrl=QUEUE_URL,
        MessageBody=json.dumps(message, indent=2)
    )
    print(f"[ALERT] {alert_type}: {finding['finding_id']}")

def dynamodb_table(snapshot_id, account_id):
    finding_id = f"rds-snapshot-public-{snapshot_id}"  
    
    try:
        previous_finding = table.get_item(Key={"finding_id": finding_id}).get("Item")
    except:
        previous_finding = None
    
    finding = {
        "finding_id": f"rds-snapshot-public-{snapshot_id}",
        "check_type": "rds-snapshot-public",
        "resource_type": "rds-snapshot",
        "resource": snapshot_id,
        "account_id": account_id,  
        "severity": "CRITICAL",
        "status": "ACTIVE",
        "reason": "RDS snapshot is publicly accessible (shared with 'all')",
        "detected_at": previous_finding.get("detected_at", datetime.now().isoformat()) if previous_finding else datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }

    previous_status = previous_finding.get("status") if previous_finding else None

    if previous_status != "ACTIVE":
        send_alert(finding, "state changed", previous_status)

    table.put_item(Item=finding)
    return 0

def lambda_handler(event, context):
    account_id = context.invoked_function_arn.split(":")[4]
    
    detail = event.get("detail", {})
    request_params = detail.get("requestParameters", {})
    snapshot_id = request_params.get("dBSnapshotIdentifier")
    
    if not snapshot_id:
        print("No snapshot ID in event, scanning all snapshots")
        response = rds.describe_db_snapshots()
        snapshots_to_check = response["DBSnapshots"]
    else:
        print(f"Event-driven: checking snapshot {snapshot_id}")
        try:
            response = rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)
            snapshots_to_check = response["DBSnapshots"]
        except Exception as e:
            print(f"Error fetching snapshot {snapshot_id}: {e}")
            return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}
        
    response = rds.describe_db_snapshots()
    account_id = context.invoked_function_arn.split(":")[4]
    
    current_public_snapshots = set()

    for snapshot in response["DBSnapshots"]:
        snapshot_id = snapshot["DBSnapshotIdentifier"]
        attrs_response = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snapshot_id)
        
        for attribute in attrs_response["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]:
            if attribute["AttributeName"] == "restore":
                attribute_values = attribute.get("AttributeValues", [])
                
                if "all" in attribute_values:
                    finding_id = f"rds-snapshot-public-{snapshot_id}"
                    current_public_snapshots.add(finding_id)
                    
                    print(f"[PUBLIC] Snapshot {snapshot_id} is public!")
                    dynamodb_table(snapshot_id, account_id)
                else:
                    print(f"[PRIVATE] Snapshot {snapshot_id} is private")
    
    try:
        response = table.scan(
            FilterExpression="check_type = :check_type AND #status = :status",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":check_type": "rds-snapshot-public",
                ":status": "ACTIVE"
            }
        )
        
        for item in response.get("Items", []):
            finding_id = item["finding_id"]
            
            if finding_id not in current_public_snapshots:
                item["status"] = "RESOLVED"
                item["resolved_at"] = datetime.now().isoformat()
                item["updated_at"] = datetime.now().isoformat()
                
                table.put_item(Item=item)
                send_alert(item, "state changed", "ACTIVE")
                print(f"[RESOLVED] Snapshot {item['resource']} is no longer public")
    
    except Exception as e:
        print(f"Error checking for resolved findings: {e}")

    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'RDS snapshot scan complete'})
    }
