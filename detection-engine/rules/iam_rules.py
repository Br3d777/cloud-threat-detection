"""
Detection rules for IAM-based attacks.
Detects brute force logins and privilege escalation.
"""

import os
import time
import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", 5))
BRUTE_FORCE_WINDOW = int(os.getenv("BRUTE_FORCE_WINDOW_SECONDS", 60))

HIGH_PRIV_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}

NON_ADMIN_USERS = {
    "regular-user-alice", "regular-user-bob",
    "svc-deploy-bot",
}


class IAMRuleEngine:
    def __init__(self):
        self._login_failures = defaultdict(list)

    def evaluate(self, event: dict, buffer: list) -> Optional[dict]:
        event_name = event.get("eventName", "")
        source_ip = event.get("sourceIPAddress", "unknown")
        user = event.get("userIdentity", {}).get("userName", "unknown")

        if event_name == "ConsoleLogin":
            result = event.get("responseElements", {}).get("ConsoleLogin", "")
            if result == "Failure":
                return self._check_brute_force(event, source_ip, user)

        if event_name in ("AttachUserPolicy", "PutUserPolicy"):
            return self._check_privilege_escalation(event, user)

        return None

    def _check_brute_force(self, event, ip, user):
        now = time.time()
        self._login_failures[ip].append(now)

        cutoff = now - BRUTE_FORCE_WINDOW
        self._login_failures[ip] = [t for t in self._login_failures[ip] if t >= cutoff]
        count = len(self._login_failures[ip])

        if count >= BRUTE_FORCE_THRESHOLD:
            score = min(10, 6 + (count - BRUTE_FORCE_THRESHOLD))
            return {
                "alert_id": hashlib.md5(f"bf-{ip}-{int(now)}".encode()).hexdigest()[:12],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "threat_type": "brute_force",
                "severity": score,
                "severity_label": self._label(score),
                "source_ip": ip,
                "affected_user": user,
                "affected_resource": "IAM:ConsoleLogin",
                "event_count": count,
                "description": f"{count} failed logins from {ip} in {BRUTE_FORCE_WINDOW}s",
                "mitre_technique": "T1110 - Brute Force",
                "recommended_action": "Block IP, reset credentials, enable MFA",
            }
        return None

    def _check_privilege_escalation(self, event, user):
        now = time.time()
        params = event.get("requestParameters", {}) or {}
        policy_arn = params.get("policyArn", "")

        if policy_arn in HIGH_PRIV_POLICIES and user in NON_ADMIN_USERS:
            score = 9
            return {
                "alert_id": hashlib.md5(f"privesc-{user}-{int(now)}".encode()).hexdigest()[:12],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "threat_type": "privilege_escalation",
                "severity": score,
                "severity_label": self._label(score),
                "source_ip": event.get("sourceIPAddress", "unknown"),
                "affected_user": user,
                "affected_resource": f"IAM:{policy_arn}",
                "event_count": 1,
                "description": f"Non-admin '{user}' attached high-privilege policy '{policy_arn}'",
                "mitre_technique": "T1098 - Account Manipulation",
                "recommended_action": "Detach policy, audit user activity, rotate credentials",
            }
        return None

    def _label(self, score):
        if score >= 8: return "CRITICAL"
        if score >= 5: return "HIGH"
        if score >= 3: return "MEDIUM"
        return "LOW"