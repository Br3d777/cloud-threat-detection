"""
Detection rules for S3-based attacks.
Detects bulk data exfiltration and sensitive bucket access.
"""

import os
import time
import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

EXFIL_THRESHOLD = int(os.getenv("EXFIL_OBJECT_THRESHOLD", 50))
EXFIL_WINDOW = int(os.getenv("EXFIL_WINDOW_SECONDS", 120))

SENSITIVE_BUCKETS = {
    "company-secrets",
    "company-data-prod",
    "company-data-backups",
}

KNOWN_INTERNAL_IPS = {
    "10.0.1.15", "10.0.1.22",
    "10.0.2.5", "192.168.1.10",
}


class S3RuleEngine:
    def __init__(self):
        self._get_object_tracker = defaultdict(list)

    def evaluate(self, event: dict, buffer: list) -> Optional[dict]:
        event_name = event.get("eventName", "")
        source_ip = event.get("sourceIPAddress", "unknown")
        user = event.get("userIdentity", {}).get("userName", "unknown")
        params = event.get("requestParameters", {}) or {}
        bucket = params.get("bucketName", "")

        if event_name == "GetObject":
            return self._check_bulk_exfiltration(event, source_ip, user, bucket)

        if event_name == "PutBucketPolicy":
            return self._check_bucket_policy_change(event, source_ip, user, bucket)

        return None

    def _check_bulk_exfiltration(self, event, ip, user, bucket):
        now = time.time()
        key = (ip, bucket)
        self._get_object_tracker[key].append(now)

        cutoff = now - EXFIL_WINDOW
        self._get_object_tracker[key] = [t for t in self._get_object_tracker[key] if t >= cutoff]
        count = len(self._get_object_tracker[key])

        if count >= EXFIL_THRESHOLD:
            is_external = ip not in KNOWN_INTERNAL_IPS
            score = 10 if is_external else 7
            return {
                "alert_id": hashlib.md5(f"exfil-{ip}-{bucket}-{int(now)}".encode()).hexdigest()[:12],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "threat_type": "data_exfiltration",
                "severity": score,
                "severity_label": self._label(score),
                "source_ip": ip,
                "affected_user": user,
                "affected_resource": f"S3:{bucket}",
                "event_count": count,
                "description": f"{count} GetObject calls from {ip} on '{bucket}' in {EXFIL_WINDOW}s",
                "mitre_technique": "T1530 - Data from Cloud Storage",
                "recommended_action": "Block IP, revoke credentials, enable MFA delete on S3",
            }
        return None

    def _check_bucket_policy_change(self, event, ip, user, bucket):
        now = time.time()
        return {
            "alert_id": hashlib.md5(f"bucketpolicy-{user}-{int(now)}".encode()).hexdigest()[:12],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "threat_type": "data_exfiltration",
            "severity": 7,
            "severity_label": "HIGH",
            "source_ip": ip,
            "affected_user": user,
            "affected_resource": f"S3:{bucket}:policy",
            "event_count": 1,
            "description": f"Bucket policy modified on '{bucket}' by '{user}'",
            "mitre_technique": "T1530 - Data from Cloud Storage",
            "recommended_action": "Review bucket policy, check for public access",
        }

    def _label(self, score):
        if score >= 8: return "CRITICAL"
        if score >= 5: return "HIGH"
        if score >= 3: return "MEDIUM"
        return "LOW"