import json
import boto3
from datetime import datetime
import os

ec2 = boto3.client("ec2")
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
        "remediation": "Remove 0.0.0.0/0 from security group ingress rules"
    }
    
    sqs.send_message(
        QueueUrl=QUEUE_URL,
        MessageBody=json.dumps(message, indent=2)
    )
    print(f"[ALERT] {alert_type}: {finding['finding_id']}")

def dynamodb_table(groupname, group_id, cidr, port, protocol, ownerid):
    severity = "LOW" 
    finding_id = f"security-group-public-{group_id}-{protocol}-{port}"    
    status = "ACTIVE"
    
    try:
        previous_finding = table.get_item(Key={"finding_id": finding_id}).get("Item")
    except:
        previous_finding = None

    port_mapping = {
        'list1':[-1],
        'list2':[22, 3389, 3306, 5432],
        'list3':[80, 443],
    }
    severity_mapping = {
        'list1':"CRITICAL",
        'list2':"HIGH",
        'list3':"MEDIUM",
    }
    for list_number, value in port_mapping.items():
        if port in value:
            severity = severity_mapping[list_number]
            break
    
    finding = {
        "finding_id": finding_id,
        "check_type": "security-group-public",
        "resource_type": "EC2",
        "resource": f"{groupname} ({group_id})",
        "account_id": ownerid,
        "severity": severity,
        "status": status,
        "reason": f"Security group allows public access ({cidr}) on {protocol}/{port}",
        "detected_at": previous_finding.get("detected_at", datetime.now().isoformat()) if previous_finding else datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }

    previous_status = previous_finding.get("status") if previous_finding else None

    if previous_status != "ACTIVE":
        send_alert(finding, "state changed", previous_status)

    table.put_item(Item=finding)
    print(f"{groupname} allows {cidr} on {port}")
    return 0

def lambda_handler(event, context):
    detail = event.get("detail", {})
    request_params = detail.get("requestParameters", {})
    group_id = request_params.get("groupId")
    
    if not group_id:
        print("No group ID in event, scanning all security groups")
        response = ec2.describe_security_groups()
        groups_to_check = response["SecurityGroups"]
    else:
        print(f"Event-driven: checking security group {group_id}")
        try:
            response = ec2.describe_security_groups(GroupIds=[group_id])
            groups_to_check = response["SecurityGroups"]
        except Exception as e:
            print(f"Error fetching security group {group_id}: {e}")
            return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}
        
    response = ec2.describe_security_groups()
    
    current_public_findings = set()
    
    for security_groups in response["SecurityGroups"]:
        for perms in security_groups["IpPermissions"]:
            for ip_range in perms.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0" or cidr == "::/0":
                    group_id = security_groups['GroupId']
                    port = perms.get('ToPort', -1)
                    protocol = perms.get('IpProtocol', 'all')
                    
                    finding_id = f"security-group-public-{group_id}-{protocol}-{port}"
                    current_public_findings.add(finding_id)
                    
                    dynamodb_table(
                        security_groups['GroupName'],
                        group_id,
                        cidr,
                        port,
                        protocol,
                        security_groups['OwnerId']
                    )

    try:
        response = table.scan(
            FilterExpression="check_type = :check_type AND #status = :status",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":check_type": "security-group-public",
                ":status": "ACTIVE"
            }
        )
        
        for item in response.get("Items", []):
            finding_id = item["finding_id"]
            
            if finding_id not in current_public_findings:
                item["status"] = "RESOLVED"
                item["resolved_at"] = datetime.now().isoformat()
                item["updated_at"] = datetime.now().isoformat()
                
                table.put_item(Item=item)
                send_alert(item, "state changed", "ACTIVE")
                print(f"[RESOLVED] {item['resource']} no longer has public access")
    
    except Exception as e:
        print(f"Error checking for resolved findings: {e}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({'message': f'Security group scan complete'})
    }
