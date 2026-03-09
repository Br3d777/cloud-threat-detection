"""
Detection rules for network and compute based attacks.
Detects crypto mining via GPU instances and Lambda abuse.
"""

import time
import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

MINING_INSTANCE_TYPES = {
    "p3.2xlarge", "p3.8xlarge", "p3.16xlarge",
    "p2.xlarge", "p2.8xlarge",
    "g4dn.xlarge", "g4dn.2xlarge",
    "g3.4xlarge", "g3.8xlarge",
}


class NetworkRuleEngine:
    def __init__(self):
        self._lambda_tracker = defaultdict(list)

    def evaluate(self, event: dict, buffer: list) -> Optional[dict]:
        event_name = event.get("eventName", "")
        source_ip = event.get("sourceIPAddress", "unknown")
        user = event.get("userIdentity", {}).get("userName", "unknown")

        if event_name == "RunInstances":
            return self._check_crypto_mining(event, source_ip, user)

        if event_name == "InvokeFunction":
            return self._check_lambda_abuse(event, source_ip, user)

        return None

    def _check_crypto_mining(self, event, ip, user):
        now = time.time()
        params = event.get("requestParameters", {}) or {}
        instance_type = params.get("instanceType", "")
        count = params.get("maxCount", 1)

        if instance_type not in MINING_INSTANCE_TYPES:
            return None

        score = 7
        if isinstance(count, int) and count >= 5:
            score = 9
        if isinstance(count, int) and count >= 10:
            score = 10

        return {
            "alert_id": hashlib.md5(f"mining-{ip}-{int(now)}".encode()).hexdigest()[:12],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "threat_type": "crypto_mining",
            "severity": score,
            "severity_label": self._label(score),
            "source_ip": ip,
            "affected_user": user,
            "affected_resource": f"EC2:{instance_type}x{count}",
            "event_count": count,
            "description": f"{count}x {instance_type} GPU instances launched by '{user}' — mining pattern",
            "mitre_technique": "T1496 - Resource Hijacking",
            "recommended_action": "Terminate instances immediately, audit permissions, check billing",
        }

    def _check_lambda_abuse(self, event, ip, user):
        now = time.time()
        window = 30
        self._lambda_tracker[user].append(now)

        cutoff = now - window
        self._lambda_tracker[user] = [t for t in self._lambda_tracker[user] if t >= cutoff]
        count = len(self._lambda_tracker[user])

        if count >= 15:
            score = min(10, 5 + (count // 5))
            return {
                "alert_id": hashlib.md5(f"lambda-{user}-{int(now)}".encode()).hexdigest()[:12],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "threat_type": "crypto_mining",
                "severity": score,
                "severity_label": self._label(score),
                "source_ip": ip,
                "affected_user": user,
                "affected_resource": "Lambda:InvokeFunction",
                "event_count": count,
                "description": f"{count} Lambda invocations in {window}s by '{user}' — serverless abuse",
                "mitre_technique": "T1496 - Resource Hijacking",
                "recommended_action": "Throttle Lambda, review function code, check for miner payload",
            }
        return None

    def _label(self, score):
        if score >= 8: return "CRITICAL"
        if score >= 5: return "HIGH"
        if score >= 3: return "MEDIUM"
        return "LOW"