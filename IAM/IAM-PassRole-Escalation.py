import json
import boto3
import os
from datetime import datetime

iam = boto3.client("iam")
dynamodb = boto3.resource("dynamodb")
sqs = boto3.client("sqs")

TABLE_NAME = os.environ["TABLE_NAME"]
QUEUE_URL = os.environ["QUEUE_URL"]

table = dynamodb.Table(TABLE_NAME)

EXECUTION_SERVICES = [
    "lambda:CreateFunction",
    "lambda:UpdateFunctionConfiguration",
    "ec2:RunInstances",
    "ecs:RunTask",
    "cloudformation:CreateStack"
]


def send_alert(finding, previous_status):
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
        "principal": finding["principal"],
        "severity": finding["severity"],
        "status": finding["status"],
        "reason": finding["reason"],
        "account_id": finding["account_id"],
        "timestamp": datetime.utcnow().isoformat(),
        "remediation": "Restrict iam:PassRole and remove execution permissions or scope role resources"
    }

    sqs.send_message(
        QueueUrl=QUEUE_URL,
        MessageBody=json.dumps(message, indent=2)
    )

    print(f"[ALERT] {alert_type}: {finding['finding_id']}")


def write_finding(principal, account_id, exploit_path):
    finding_id = f"iam-passrole-escalation-{principal}"

    try:
        previous = table.get_item(Key={"finding_id": finding_id}).get("Item")
    except:
        previous = None

    finding = {
        "finding_id": finding_id,
        "check_type": "iam-passrole-escalation",
        "resource_type": "iam-principal",
        "principal": principal,
        "account_id": account_id,
        "severity": "CRITICAL",
        "status": "ACTIVE",
        "reason": "Principal can pass roles and invoke execution services, enabling privilege escalation",
        "exploit_path": exploit_path,
        "detected_at": previous.get("detected_at", datetime.utcnow().isoformat()) if previous else datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }

    previous_status = previous.get("status") if previous else None

    if previous_status != "ACTIVE":
        send_alert(finding, previous_status)

    table.put_item(Item=finding)


def extract_allowed_actions(policy_document):
    actions = set()

    for stmt in policy_document.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue

        action = stmt.get("Action", [])
        if isinstance(action, str):
            actions.add(action.lower())
        else:
            for a in action:
                actions.add(a.lower())

    return actions

def principal_has_permissions(attached_policies):
    allowed = set()

    for policy in attached_policies:
        policy_arn = policy["PolicyArn"]

        policy_meta = iam.get_policy(PolicyArn=policy_arn)
        default_version = policy_meta["Policy"]["DefaultVersionId"]

        version = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=default_version
        )

        allowed |= extract_allowed_actions(
            version["PolicyVersion"]["Document"]
        )

    return allowed


def lambda_handler(event, context):
    account_id = context.invoked_function_arn.split(":")[4]
    users = iam.list_users()["Users"]
    
    current_vulnerable_principals = set()

    for user in users:
        user_name = user["UserName"]
        attached = iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]
        inline = iam.list_user_policies(UserName=user_name)["PolicyNames"]
        allowed_actions = principal_has_permissions(attached)

        for policy_name in inline:
            policy = iam.get_user_policy(
                UserName=user_name,
                PolicyName=policy_name
            )
            allowed_actions |= extract_allowed_actions(policy["PolicyDocument"])

        has_passrole = any(
            a == "iam:passrole" or a == "iam:*" or a == "*"
            for a in allowed_actions
        )

        has_execution = any(
            exec_perm.lower() in allowed_actions or "*:*" in allowed_actions
            for exec_perm in EXECUTION_SERVICES
        )

        if has_passrole and has_execution:
            finding_id = f"iam-passrole-escalation-{user_name}"
            current_vulnerable_principals.add(finding_id)
            
            exploit_path = [
                "iam:PassRole",
                "execution-service",
                "privileged-role-assumption"
            ]

            print(f"[CRITICAL] Privilege escalation path found for user: {user_name}")
            write_finding(user_name, account_id, exploit_path)
    
    try:
        response = table.scan(
            FilterExpression="check_type = :check_type AND #status = :status",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":check_type": "iam-passrole-escalation",
                ":status": "ACTIVE"
            }
        )
        
        for item in response.get("Items", []):
            finding_id = item["finding_id"]
            
            if finding_id not in current_vulnerable_principals:
                item["status"] = "RESOLVED"
                item["resolved_at"] = datetime.utcnow().isoformat()
                item["updated_at"] = datetime.utcnow().isoformat()
                
                table.put_item(Item=item)
                send_alert(item, "ACTIVE")
                print(f"[RESOLVED] User {item['principal']} no longer has escalation path")
    
    except Exception as e:
        print(f"Error checking for resolved findings: {e}")

    return {
        "statusCode": 200,
        "body": json.dumps({"message": "IAM PassRole escalation scan complete"})
    }
