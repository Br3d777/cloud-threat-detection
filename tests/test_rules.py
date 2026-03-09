"""
Unit tests for all detection rules.
These run automatically in GitHub Actions on every push.
"""

import sys
import os
import time
import pytest
from datetime import datetime, timezone

# Allow imports from detection-engine folder
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'detection-engine'))

# Mock the detector module so rules can import it during tests
import types
mock = types.ModuleType('detector')

class MockAlert:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

mock.ThreatAlert = MockAlert
mock.severity_label = lambda s: "CRITICAL" if s>=8 else "HIGH" if s>=5 else "MEDIUM" if s>=3 else "LOW"
sys.modules['detector'] = mock

from rules.iam_rules import IAMRuleEngine
from rules.s3_rules import S3RuleEngine
from rules.network_rules import NetworkRuleEngine


# ---- Helpers ----

def login_event(success, ip, user="test-user"):
    return {
        "eventName": "ConsoleLogin",
        "eventTime": datetime.now(timezone.utc).isoformat(),
        "sourceIPAddress": ip,
        "userIdentity": {"userName": user},
        "responseElements": {"ConsoleLogin": "Success" if success else "Failure"},
    }

def iam_event(name, user, policy, target=None):
    return {
        "eventName": name,
        "eventTime": datetime.now(timezone.utc).isoformat(),
        "sourceIPAddress": "10.0.1.15",
        "userIdentity": {"userName": user},
        "requestParameters": {"policyArn": policy, "userName": target or user},
    }

def s3_event(name, ip, bucket, user="test-user"):
    return {
        "eventName": name,
        "eventTime": datetime.now(timezone.utc).isoformat(),
        "sourceIPAddress": ip,
        "userIdentity": {"userName": user},
        "requestParameters": {"bucketName": bucket, "key": "test/file.dat"},
    }

def ec2_event(instance_type, count, ip):
    return {
        "eventName": "RunInstances",
        "eventTime": datetime.now(timezone.utc).isoformat(),
        "sourceIPAddress": ip,
        "userIdentity": {"userName": "svc-deploy-bot"},
        "requestParameters": {"instanceType": instance_type, "maxCount": count, "minCount": count},
    }


# ---- Brute Force Tests ----

class TestBruteForce:
    def setup_method(self):
        self.engine = IAMRuleEngine()

    def test_below_threshold_no_alert(self):
        for _ in range(4):
            result = self.engine.evaluate(login_event(False, "1.1.1.1"), [])
        assert result is None

    def test_at_threshold_triggers(self):
        result = None
        for _ in range(5):
            result = self.engine.evaluate(login_event(False, "2.2.2.2"), [])
        assert result is not None
        assert result["threat_type"] == "brute_force"

    def test_high_count_is_critical(self):
        result = None
        for _ in range(15):
            result = self.engine.evaluate(login_event(False, "3.3.3.3"), [])
        assert result["severity"] >= 8

    def test_different_ips_no_alert(self):
        for i in range(10):
            result = self.engine.evaluate(login_event(False, f"10.0.0.{i}"), [])
        assert result is None

    def test_success_no_alert(self):
        for _ in range(10):
            result = self.engine.evaluate(login_event(True, "4.4.4.4"), [])
        assert result is None


# ---- Privilege Escalation Tests ----

class TestPrivEsc:
    def setup_method(self):
        self.engine = IAMRuleEngine()

    def test_non_admin_attach_admin_triggers(self):
        event = iam_event("AttachUserPolicy", "regular-user-alice", "arn:aws:iam::aws:policy/AdministratorAccess")
        result = self.engine.evaluate(event, [])
        assert result is not None
        assert result["threat_type"] == "privilege_escalation"

    def test_readonly_policy_no_alert(self):
        event = iam_event("AttachUserPolicy", "regular-user-alice", "arn:aws:iam::aws:policy/ReadOnlyAccess")
        result = self.engine.evaluate(event, [])
        assert result is None


# ---- S3 Exfiltration Tests ----

class TestS3Exfil:
    def setup_method(self):
        self.engine = S3RuleEngine()

    def test_bulk_download_triggers(self):
        result = None
        for _ in range(60):
            result = self.engine.evaluate(s3_event("GetObject", "45.0.0.1", "company-secrets"), [])
        assert result is not None
        assert result["threat_type"] == "data_exfiltration"

    def test_below_threshold_no_alert(self):
        result = None
        for _ in range(30):
            result = self.engine.evaluate(s3_event("GetObject", "45.0.0.2", "company-data-prod"), [])
        assert result is None

    def test_bucket_policy_change_triggers(self):
        result = self.engine.evaluate(s3_event("PutBucketPolicy", "10.0.1.15", "company-data-prod"), [])
        assert result is not None


# ---- Crypto Mining Tests ----

class TestCryptoMining:
    def setup_method(self):
        self.engine = NetworkRuleEngine()

    def test_gpu_instance_triggers(self):
        result = self.engine.evaluate(ec2_event("p3.2xlarge", 1, "5.5.5.5"), [])
        assert result is not None
        assert result["threat_type"] == "crypto_mining"

    def test_normal_instance_no_alert(self):
        result = self.engine.evaluate(ec2_event("t3.micro", 1, "10.0.1.15"), [])
        assert result is None

    def test_many_gpu_instances_critical(self):
        result = self.engine.evaluate(ec2_event("p3.8xlarge", 12, "6.6.6.6"), [])
        assert result["severity"] >= 8