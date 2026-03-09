"""
Simulates a brute force login attack.
Fires repeated failed login attempts from one IP address.
"""

import time
import random
import json
from datetime import datetime, timezone

ATTACKER_IPS = [
    "185.220.101.47",
    "45.142.212.100",
    "194.165.16.11",
]

TARGET_USERNAMES = [
    "admin", "regular-user-alice",
    "regular-user-bob", "root", "test",
]


class BruteForceScenario:
    def __init__(self, write_event_fn):
        self.write_event = write_event_fn
        self.attacker_ip = random.choice(ATTACKER_IPS)
        self.target_user = random.choice(TARGET_USERNAMES)

    def _make_login_event(self, success: bool) -> dict:
        return {
            "eventName": "ConsoleLogin",
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "sourceIPAddress": self.attacker_ip,
            "userIdentity": {"userName": self.target_user},
            "responseElements": {
                "ConsoleLogin": "Success" if success else "Failure"
            },
            "_meta": {"scenario": "brute_force"}
        }

    def run(self):
        print(f"[BruteForce] Attacker {self.attacker_ip} targeting {self.target_user}")
        num_failures = random.randint(8, 12)

        for i in range(num_failures):
            event = self._make_login_event(success=False)
            self.write_event(event)
            time.sleep(0.2)

        # Final successful login
        print(f"[BruteForce] Attacker succeeded after {num_failures} attempts")
        self.write_event(self._make_login_event(success=True))
```

---
