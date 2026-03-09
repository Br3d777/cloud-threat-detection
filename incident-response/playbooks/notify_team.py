"""
Playbook: Notify the security team of a detected threat.
Sends alerts to console, Slack, and SNS.
"""

import os
import json
import logging
import boto3
from datetime import datetime, timezone

log = logging.getLogger(__name__)

SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "")
AWS_ENDPOINT = os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566")

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
}


class NotifyTeamPlaybook:
    def __init__(self):
        self.sns = boto3.client(
            "sns",
            endpoint_url=AWS_ENDPOINT,
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "test"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "test"),
            region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
        )

    def execute(self, alert: dict, priority: str = "high") -> dict:
        emoji = SEVERITY_EMOJI.get(alert.get("severity_label", "LOW"), "⚪")
        channels = []

        # Always log to console
        self._log_to_console(alert, emoji)
        channels.append("console")

        # Slack (if configured)
        if SLACK_WEBHOOK:
            self._send_slack(alert, emoji)
            channels.append("slack")
        else:
            channels.append("slack:skipped")

        # SNS
        self._send_sns(alert)
        channels.append("sns")

        return {
            "playbook": "notify_team",
            "alert_id": alert.get("alert_id"),
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "channels": channels,
            "status": "completed",
        }

    def _log_to_console(self, alert, emoji):
        log.warning("=" * 55)
        log.warning(f"  {emoji} THREAT ALERT — {alert.get('severity_label')} [{alert.get('severity')}/10]")
        log.warning(f"  Type:     {alert.get('threat_type', '').upper()}")
        log.warning(f"  Desc:     {alert.get('description')}")
        log.warning(f"  IP:       {alert.get('source_ip')}")
        log.warning(f"  User:     {alert.get('affected_user')}")
        log.warning(f"  MITRE:    {alert.get('mitre_technique')}")
        log.warning(f"  Action:   {alert.get('recommended_action')}")
        log.warning("=" * 55)

    def _send_slack(self, alert, emoji):
        try:
            import requests
            payload = {
                "text": f"{emoji} *Threat Detected* — {alert.get('severity_label')}",
                "attachments": [{
                    "color": "danger" if alert.get("severity_label") == "CRITICAL" else "warning",
                    "fields": [
                        {"title": "Type", "value": alert.get("threat_type"), "short": True},
                        {"title": "Severity", "value": f"{alert.get('severity')}/10", "short": True},
                        {"title": "Description", "value": alert.get("description"), "short": False},
                    ]
                }]
            }
            requests.post(SLACK_WEBHOOK, json=payload, timeout=5)
        except Exception as e:
            log.warning(f"  [NOTIFY] Slack failed: {e}")

    def _send_sns(self, alert):
        try:
            self.sns.publish(
                TopicArn="arn:aws:sns:us-east-1:123456789012:threat-alerts",
                Message=json.dumps(alert),
                Subject=f"[{alert.get('severity_label')}] {alert.get('threat_type')}",
            )
        except Exception:
            pass