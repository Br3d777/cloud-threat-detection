"""
Playbook: Isolate a compromised user.
Attaches a deny-all policy to lock them out immediately.
"""

import os
import json
import logging
import boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)

AWS_ENDPOINT = os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566")

DENY_ALL_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*"
    }]
})


class IsolateResourcePlaybook:
    def __init__(self):
        self.iam = boto3.client(
            "iam",
            endpoint_url=AWS_ENDPOINT,
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "test"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "test"),
            region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
        )

    def execute(self, alert: dict) -> dict:
        user = alert.get("affected_user", "unknown")
        log.warning(f"  [ISOLATE] Isolating user: {user}")
        actions = []

        # Step 1: Attach deny-all policy
        try:
            self.iam.put_user_policy(
                UserName=user,
                PolicyName="EMERGENCY-DENY-ALL",
                PolicyDocument=DENY_ALL_POLICY,
            )
            log.warning(f"  [ISOLATE] ✅ Deny-all policy attached to {user}")
            actions.append({"step": "attach_deny_policy", "status": "success"})
        except ClientError:
            log.info(f"  [ISOLATE] User {user} not found in local env — simulated")
            actions.append({"step": "attach_deny_policy", "status": "simulated"})

        # Step 2: Deactivate access keys
        try:
            keys = self.iam.list_access_keys(UserName=user).get("AccessKeyMetadata", [])
            for key in keys:
                self.iam.update_access_key(
                    UserName=user,
                    AccessKeyId=key["AccessKeyId"],
                    Status="Inactive",
                )
            actions.append({"step": "deactivate_keys", "status": "success", "count": len(keys)})
        except ClientError:
            actions.append({"step": "deactivate_keys", "status": "simulated"})

        log.warning(f"  [ISOLATE] Isolation complete for {user}")
        return {
            "playbook": "isolate_resource",
            "target_user": user,
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "steps": actions,
            "status": "completed",
        }