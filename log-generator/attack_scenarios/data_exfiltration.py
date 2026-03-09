"""
Simulates a data exfiltration attack.
An attacker rapidly downloads many files from S3 storage.
"""

import time
import random
from datetime import datetime, timezone

ATTACKER_IPS = [
    "45.142.212.100",
    "185.220.101.47",
    "91.108.4.55",
]

SENSITIVE_BUCKETS = [
    "company-secrets",
    "company-data-prod",
]

SENSITIVE_FILES = [
    "internal/employee-records.csv",
    "financial/q4-2024-results.pdf",
    "keys/api-keys.json",
    "backup/db-dump-2024.sql.gz",
    "config/production.env",
]


class DataExfiltrationScenario:
    def __init__(self, write_event_fn):
        self.write_event = write_event_fn
        self.attacker_ip = random.choice(ATTACKER_IPS)
        self.target_bucket = random.choice(SENSITIVE_BUCKETS)
        self.num_files = random.randint(55, 90)

    def _make_s3_event(self, event_name: str, bucket: str, key: str = None) -> dict:
        params = {"bucketName": bucket}
        if key:
            params["key"] = key
        return {
            "eventName": event_name,
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "sourceIPAddress": self.attacker_ip,
            "userIdentity": {"userName": "regular-user-alice"},
            "requestParameters": params,
            "_meta": {"scenario": "data_exfiltration"}
        }

    def run(self):
        print(f"[Exfil] Attacker {self.attacker_ip} targeting {self.target_bucket}")

        # Step 1: List all buckets
        self.write_event(self._make_s3_event("ListBuckets", ""))
        time.sleep(0.3)

        # Step 2: List files in target bucket
        self.write_event(self._make_s3_event("ListObjects", self.target_bucket))
        time.sleep(0.3)

        # Step 3: Rapidly download many files
        print(f"[Exfil] Downloading {self.num_files} files...")
        for i in range(self.num_files):
            key = random.choice(SENSITIVE_FILES)
            self.write_event(self._make_s3_event("GetObject", self.target_bucket, f"{key}-{i}"))
            time.sleep(0.05)

        print(f"[Exfil] Done — {self.num_files} files downloaded")