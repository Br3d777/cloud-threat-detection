"""
Simulates a privilege escalation attack.
A regular user attaches admin permissions to themselves.
"""

import time
import random
from datetime import datetime, timezone

ATTACKER_USERS = [
    "regular-user-alice",
    "regular-user-bob",
]

ATTACKER_IPS = [
    "10.0.1.15",
    "10.0.1.22",
]

HIGH_PRIV_POLICIES = [
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
]


class PrivilegeEscalationScenario:
    def __init__(self, write_event_fn):
        self.write_event = write_event_fn
        self.attacker = random.choice(ATTACKER_USERS)
        self.attacker_ip = random.choice(ATTACKER_IPS)
        self.policy = random.choice(HIGH_PRIV_POLICIES)
        self.backdoor_user = f"svc-temp-{random.randint(1000, 9999)}"

    def _make_iam_event(self, event_name: str, params: dict) -> dict:
        return {
            "eventName": event_name,
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "sourceIPAddress": self.attacker_ip,
            "userIdentity": {"userName": self.attacker},
            "requestParameters": params,
            "_meta": {"scenario": "privilege_escalation"}
        }

    def run(self):
        print(f"[PrivEsc] {self.attacker} escalating privileges...")

        # Step 1: Attach admin policy to self
        self.write_event(self._make_iam_event("AttachUserPolicy", {
            "userName": self.attacker,
            "policyArn": self.policy,
        }))
        time.sleep(0.5)

        # Step 2: Create backdoor user
        self.write_event(self._make_iam_event("CreateUser", {
            "userName": self.backdoor_user,
        }))
        time.sleep(0.3)

        # Step 3: Give backdoor user admin access
        self.write_event(self._make_iam_event("AttachUserPolicy", {
            "userName": self.backdoor_user,
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        }))
        time.sleep(0.2)

        # Step 4: Create access key for backdoor user
        self.write_event(self._make_iam_event("CreateAccessKey", {
            "userName": self.backdoor_user,
        }))
        print(f"[PrivEsc] Backdoor user {self.backdoor_user} created")