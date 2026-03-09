"""
Incident response orchestrator.
Watches for alerts and routes them to the correct playbook.
"""

import os
import json
import time
import logging
from pathlib import Path
from datetime import datetime, timezone

from playbooks.isolate_resource import IsolateResourcePlaybook
from playbooks.notify_team import NotifyTeamPlaybook

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [RESPONDER] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

ALERTS_DIR = Path(os.getenv("ALERTS_DIR", "/tmp/alerts"))
INCIDENTS_DIR = Path(os.getenv("INCIDENTS_DIR", "/tmp/incidents"))
INCIDENTS_DIR.mkdir(parents=True, exist_ok=True)

PROCESSED = set()
INCIDENT_COUNT = 0


class IncidentResponder:
    def __init__(self):
        self.isolator = IsolateResourcePlaybook()
        self.notifier = NotifyTeamPlaybook()
        log.info("Incident responder started...")

    def handle(self, alert: dict):
        global INCIDENT_COUNT
        severity = alert.get("severity", 0)
        label = alert.get("severity_label", "LOW")
        actions = []

        if severity >= 8:
            log.warning(f"🔴 CRITICAL — running full response playbook")
            actions.append(self.isolator.execute(alert))
            actions.append(self.notifier.execute(alert, priority="critical"))

        elif severity >= 5:
            log.warning(f"🟠 HIGH — notifying team")
            actions.append(self.notifier.execute(alert, priority="high"))

        elif severity >= 3:
            log.info(f"🟡 MEDIUM — logging incident")
            actions.append({"action": "monitor", "status": "watching"})

        else:
            log.debug(f"🔵 LOW — logged only")

        # Save incident record
        INCIDENT_COUNT += 1
        incident = {
            "incidentId": f"INC-{INCIDENT_COUNT:04d}",
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "status": "open",
            "alert": alert,
            "actions": actions,
        }
        path = INCIDENTS_DIR / f"incident-INC-{INCIDENT_COUNT:04d}.json"
        path.write_text(json.dumps(incident, indent=2))
        log.info(f"📋 Incident created: INC-{INCIDENT_COUNT:04d}")

    def watch(self):
        log.info(f"Watching {ALERTS_DIR} for alerts...")
        while True:
            try:
                files = sorted(ALERTS_DIR.glob("alert-*.json"))
                new_files = [f for f in files if f.name not in PROCESSED]

                for f in new_files:
                    try:
                        alert = json.loads(f.read_text())
                        self.handle(alert)
                        PROCESSED.add(f.name)
                    except Exception as e:
                        log.error(f"Error handling {f.name}: {e}")

            except Exception as e:
                log.error(f"Watch error: {e}")

            time.sleep(1)


if __name__ == "__main__":
    log.info("=" * 50)
    log.info("  Incident Responder")
    log.info("=" * 50)
    responder = IncidentResponder()
    responder.watch()