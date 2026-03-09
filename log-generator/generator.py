"""
Main log generator.
Simulates normal cloud traffic mixed with attack scenarios.
"""

import os
import json
import time
import random
from pathlib import Path
from datetime import datetime, timezone

from attack_scenarios.brute_force import BruteForceScenario
from attack_scenarios.privilege_escalation import PrivilegeEscalationScenario
from attack_scenarios.data_exfiltration import DataExfiltrationScenario
from attack_scenarios.crypto_mining import CryptoMiningScenario

EVENTS_DIR = Path(os.getenv("EVENTS_DIR", "/tmp/events"))
EVENTS_DIR.mkdir(parents=True, exist_ok=True)

NORMAL_USERS = [
    "regular-user-alice", "regular-user-bob",
    "svc-deploy-bot", "admin-user-carlos",
]

NORMAL_IPS = [
    "10.0.1.15", "10.0.1.22",
    "192.168.1.10", "10.0.2.5",
]

NORMAL_EVENTS = [
    "GetObject", "ListBuckets", "DescribeInstances",
    "GetCallerIdentity", "ListUsers", "PutObject",
]


def write_event(event: dict):
    ts = int(time.time() * 1000)
    rand = random.randint(1000, 9999)
    path = EVENTS_DIR / f"event-{ts}-{rand}.json"
    path.write_text(json.dumps(event, indent=2))
    print(f"  → {event['eventName']} | user={event['userIdentity']['userName']} | ip={event['sourceIPAddress']}")


def emit_normal_event():
    event = {
        "eventName": random.choice(NORMAL_EVENTS),
        "eventTime": datetime.now(timezone.utc).isoformat(),
        "sourceIPAddress": random.choice(NORMAL_IPS),
        "userIdentity": {"userName": random.choice(NORMAL_USERS)},
        "requestParameters": {},
        "_meta": {"scenario": "normal"}
    }
    write_event(event)


def main():
    print("=" * 50)
    print("  Cloud Threat Detection - Log Generator")
    print("=" * 50)

    scenarios = [
        BruteForceScenario,
        PrivilegeEscalationScenario,
        DataExfiltrationScenario,
        CryptoMiningScenario,
    ]

    cycle = 0
    while True:
        cycle += 1

        # Emit normal events
        for _ in range(random.randint(3, 6)):
            emit_normal_event()
            time.sleep(0.5)

        # Every 10 cycles inject a random attack
        if cycle % 10 == 0:
            scenario_class = random.choice(scenarios)
            scenario = scenario_class(write_event_fn=write_event)
            scenario.run()

        time.sleep(2)


if __name__ == "__main__":
    main()