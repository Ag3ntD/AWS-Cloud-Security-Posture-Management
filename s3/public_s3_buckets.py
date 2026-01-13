import json
import boto3
from datetime import datetime
from botocore.exceptions import ClientError
from decimal import Decimal
import os

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
sqs = boto3.client('sqs')

TABLE_NAME = os.environ["TABLE_NAME"]       
QUEUE_URL = os.environ.get("QUEUE_URL")     
# Set TABLE_NAME and QUEUE_URL in enviroment variables

table = dynamodb.Table(TABLE_NAME)

def decimal_to_native(obj):
    if isinstance(obj, list):
        return [decimal_to_native(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: decimal_to_native(v) for k, v in obj.items()}
    elif isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    else:
        return obj

def generate_finding_id(check_type, resource_type, resource_name):
    """Generate unique finding ID."""
    return f"{check_type}-{resource_type}-{resource_name}"

def get_previous_finding(finding_id):
    """Retrieve previous finding state from DynamoDB."""
    try:
        response = table.get_item(Key={"finding_id": finding_id})
        return response.get("Item")
    except Exception as e:
        print(f"Error retrieving finding {finding_id}: {e}")
        return None

def create_finding(bucket_name, policy_public, acl_public, account_id):
    """Create normalized finding object."""
    finding_id = generate_finding_id("s3-public", "bucket", bucket_name)
    
    # Determine reason
    reasons = []
    if policy_public:
        reasons.append("Bucket policy allows public access")
    if acl_public:
        reasons.append("Bucket ACL grants public access")
    
    finding = {
        "finding_id": finding_id,
        "check_type": "s3-public",
        "resource_type": "bucket",
        "resource": bucket_name,
        "account_id": account_id,
        "severity": "HIGH",
        "status": "ACTIVE",
        "reason": "; ".join(reasons),
        "policy_public": policy_public,
        "acl_public": acl_public,
        "detected_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }
    
    return finding

def determine_state_transition(previous_finding, is_public):
    """
    Determine if finding state changed.
    Returns: (state_changed, new_status, previous_status)
    """
    if previous_finding is None:
        # New finding
        if is_public:
            return (True, "ACTIVE", None) 
        else:
            return (False, None, None)  # Not public, no finding
    
    previous_status = previous_finding.get("status")
    
    if is_public and previous_status == "RESOLVED":
        return (True, "ACTIVE", "RESOLVED")
    elif is_public and previous_status == "ACTIVE":
        return (False, "ACTIVE", "ACTIVE")
    elif not is_public and previous_status == "ACTIVE":
        return (True, "RESOLVED", "ACTIVE")
    elif not is_public and previous_status == "RESOLVED":
        return (False, "RESOLVED", "RESOLVED")
    
    return (False, None, None)

def store_finding(finding):
    """Store finding in DynamoDB."""
    table.put_item(Item=finding)

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
        "remediation": "Enable Block Public Access or remove public grants from bucket ACL/policy"
    }
    
    sqs.send_message(
        QueueUrl=QUEUE_URL,
        MessageBody=json.dumps(message, indent=2)
    )
    
    print(f"[ALERT] {alert_type}: {finding['finding_id']}")

def check_bucket_public_status(bucket_name):
    """Check if S3 bucket is publicly accessible."""
    policy_public = False
    acl_public = False
    block_policy = False
    block_acls = False

    # Check bucket policy
    try:
        policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
        policy_public = policy_status["PolicyStatus"]["IsPublic"]
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
            print(f"Error checking policy for {bucket_name}: {e}")

    # Check BPA
    try:
        bpa = s3.get_public_access_block(Bucket=bucket_name)
        config = bpa["PublicAccessBlockConfiguration"]
        block_policy = config.get("BlockPublicPolicy", False)
        block_acls = config.get("BlockPublicAcls", False)
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
            print(f"Error checking BPA for {bucket_name}: {e}")

    # Check ACL
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if (grantee.get("Type") == "Group" and 
                "AllUsers" in grantee.get("URI", "")):
                acl_public = True
                break
    except ClientError as e:
        print(f"Error checking ACL for {bucket_name}: {e}")

    is_public = (
        (policy_public and not block_policy) or
        (acl_public and not block_acls)
    )
    
    return is_public, policy_public, acl_public

def lambda_handler(event, context):
    response = s3.list_buckets()
    buckets = response.get("Buckets", [])
    
    account_id = context.invoked_function_arn.split(":")[4]
    
    active_findings = []
    resolved_findings = []
    new_findings = []
    reopened_findings = []
    
    for bucket in buckets:
        name = bucket["Name"]
        finding_id = generate_finding_id("s3-public", "bucket", name)
        
        # Check current state
        is_public, policy_public, acl_public = check_bucket_public_status(name)
        
        # Get previous state
        previous_finding = get_previous_finding(finding_id)
        
        # Determine state transition
        state_changed, new_status, previous_status = determine_state_transition(
            previous_finding, is_public
        )
        
        if is_public:
            # Create/update finding
            finding = create_finding(name, policy_public, acl_public, account_id)
            
            # Preserve history
            if previous_finding:
                finding["detected_at"] = previous_finding.get(
                    "detected_at", 
                    finding["detected_at"]
                )
                finding["first_seen"] = previous_finding.get("detected_at")
                
                # Track reopening
                if previous_status == "RESOLVED":
                    finding["reopened_at"] = datetime.now().isoformat()
                    finding["times_reopened"] = previous_finding.get("times_reopened", 0) + 1
                    reopened_findings.append(finding)
                else:
                    finding["times_reopened"] = previous_finding.get("times_reopened", 0)
            else:
                new_findings.append(finding)
            
            store_finding(finding)
            active_findings.append(finding)
            
            # Alert on state changes
            if state_changed:
                send_alert(finding, state_changed, previous_status)
            
            print(f"[ACTIVE] {name}")
            
        elif previous_finding and previous_finding.get("status") == "ACTIVE":
            # Bucket was public, now private - mark as resolved
            finding = previous_finding.copy()
            finding["status"] = "RESOLVED"
            finding["resolved_at"] = datetime.now().isoformat()
            finding["updated_at"] = datetime.now().isoformat()
            
            store_finding(finding)
            resolved_findings.append(finding)
            
            # Send resolution alert
            send_alert(finding, True, "ACTIVE")
            
            print(f"[RESOLVED] {name}")
        else:
            print(f"[COMPLIANT] {name}")
    
    # Summary
    summary = {
        "scan_time": datetime.now().isoformat(),
        "account_id": account_id,
        "total_buckets": len(buckets),
        "active_findings": len(active_findings),
        "new_findings": len(new_findings),
        "reopened_findings": len(reopened_findings),
        "resolved_findings": len(resolved_findings),
        "findings": active_findings
    }
    
    print(f"\n=== SCAN SUMMARY ===")
    print(f"Total buckets: {len(buckets)}")
    print(f"Active findings: {len(active_findings)}")
    print(f"New findings: {len(new_findings)}")
    print(f"Reopened findings: {len(reopened_findings)}")
    print(f"Resolved findings: {len(resolved_findings)}")
    
    return {
        "statusCode": 200,
        "body": json.dumps(decimal_to_native(summary), indent=2)
    }
