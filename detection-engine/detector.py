"""
Core detection engine.
Watches for new events and runs them through all detection rules.
"""

import os
import json
import time
import logging
from pathlib import Path
from collections import deque

from rules.iam_rules import IAMRuleEngine
from rules.s3_rules import S3RuleEngine
from rules.network_rules import NetworkRuleEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [DETECTOR] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

EVENTS_DIR = Path(os.getenv("EVENTS_DIR", "/tmp/events"))
ALERTS_DIR = Path(os.getenv("ALERTS_DIR", "/tmp/alerts"))
ALERTS_DIR.mkdir(parents=True, exist_ok=True)

ALERT_SEVERITY_MIN = int(os.getenv("ALERT_SEVERITY_MIN", 3))
PROCESSED = set()


def write_alert(alert: dict):
    path = ALERTS_DIR / f"alert-{alert['alert_id']}.json"
    path.write_text(json.dumps(alert, indent=2))

    labels = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵"
    }
    emoji = labels.get(alert["severity_label"], "⚪")
    log.warning(f"{emoji} [{alert['severity_label']}] {alert['threat_type'].upper()}")
    log.warning(f"   {alert['description']}")
    log.warning(f"   IP: {alert['source_ip']} | User: {alert['affected_user']}")


class DetectionEngine:
    def __init__(self):
        self.iam = IAMRuleEngine()
        self.s3 = S3RuleEngine()
        self.network = NetworkRuleEngine()
        self.buffer = deque(maxlen=1000)
        log.info("Detection engine started — watching for threats...")

    def process_event(self, event: dict):
        self.buffer.append(event)
        buf = list(self.buffer)

        alert = (
            self.iam.evaluate(event, buf) or
            self.s3.evaluate(event, buf) or
            self.network.evaluate(event, buf)
        )

        if alert and alert["severity"] >= ALERT_SEVERITY_MIN:
            write_alert(alert)

    def watch(self):
        log.info(f"Watching {EVENTS_DIR} for events...")
        while True:
            try:
                files = sorted(EVENTS_DIR.glob("event-*.json"))
                new_files = [f for f in files if f.name not in PROCESSED]

                for f in new_files:
                    try:
                        event = json.loads(f.read_text())
                        self.process_event(event)
                        PROCESSED.add(f.name)
                    except Exception as e:
                        log.error(f"Error processing {f.name}: {e}")

            except Exception as e:
                log.error(f"Watch error: {e}")

            time.sleep(0.5)


if __name__ == "__main__":
    log.info("=" * 50)
    log.info("  Cloud Threat Detection Engine")
    log.info("=" * 50)
    engine = DetectionEngine()
    engine.watch()