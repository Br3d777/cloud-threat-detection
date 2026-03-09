"""
Simulates a crypto mining attack.
An attacker launches powerful GPU instances to mine cryptocurrency.
"""

import time
import random
from datetime import datetime, timezone

ATTACKER_IPS = [
    "45.142.212.100",
    "185.220.101.47",
]

MINING_INSTANCE_TYPES = [
    "p3.2xlarge",
    "p3.8xlarge",
    "g4dn.xlarge",
    "g3.4xlarge",
]


class CryptoMiningScenario:
    def __init__(self, write_event_fn):
        self.write_event = write_event_fn
        self.attacker_ip = random.choice(ATTACKER_IPS)
        self.instance_type = random.choice(MINING_INSTANCE_TYPES)
        self.num_instances = random.randint(5, 15)

    def _make_ec2_event(self, event_name: str, params: dict) -> dict:
        return {
            "eventName": event_name,
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "sourceIPAddress": self.attacker_ip,
            "userIdentity": {"userName": "svc-deploy-bot"},
            "requestParameters": params,
            "_meta": {"scenario": "crypto_mining"}
        }

    def _make_lambda_event(self) -> dict:
        return {
            "eventName": "InvokeFunction",
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "sourceIPAddress": self.attacker_ip,
            "userIdentity": {"userName": "svc-deploy-bot"},
            "requestParameters": {"functionName": "mining-worker"},
            "_meta": {"scenario": "crypto_mining"}
        }

    def run(self):
        print(f"[CryptoMining] Launching {self.num_instances}x {self.instance_type}")

        # Step 1: Launch GPU instances
        self.write_event(self._make_ec2_event("RunInstances", {
            "instanceType": self.instance_type,
            "maxCount": self.num_instances,
            "minCount": self.num_instances,
        }))
        time.sleep(0.5)

        # Step 2: Check instances are running
        self.write_event(self._make_ec2_event("DescribeInstances", {}))
        time.sleep(0.3)

        # Step 3: Abuse Lambda functions at scale
        print(f"[CryptoMining] Invoking Lambda functions...")
        for i in range(random.randint(20, 40)):
            self.write_event(self._make_lambda_event())
            time.sleep(0.1)

        print(f"[CryptoMining] Mining infrastructure deployed")