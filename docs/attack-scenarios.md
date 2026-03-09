\# ⚔️ Attack Scenarios



\## 1. Brute Force / Credential Stuffing

\*\*File:\*\* `log-generator/attack\_scenarios/brute\_force.py`



Simulates an automated tool repeatedly trying passwords against an account.



\*\*How it works:\*\*

\- Fires 8–12 failed ConsoleLogin events from one IP

\- Then fires one successful login (attacker gets in)



\*\*Detection:\*\*

\- 5+ failed logins from same IP within 60 seconds

\- Severity scales with number of attempts



\*\*MITRE:\*\* T1110 - Brute Force



---



\## 2. Privilege Escalation

\*\*File:\*\* `log-generator/attack\_scenarios/privilege\_escalation.py`



Simulates a compromised regular user giving themselves admin access.



\*\*How it works:\*\*

\- Attaches AdministratorAccess policy to own account

\- Creates a backdoor user

\- Gives backdoor user admin access

\- Creates access keys for backdoor user



\*\*Detection:\*\*

\- Non-admin user attaching high privilege policy

\- User creation following policy escalation



\*\*MITRE:\*\* T1098 - Account Manipulation



---



\## 3. Data Exfiltration

\*\*File:\*\* `log-generator/attack\_scenarios/data\_exfiltration.py`



Simulates an attacker bulk downloading files from S3 storage.



\*\*How it works:\*\*

\- Lists all buckets

\- Lists objects in sensitive bucket

\- Rapidly downloads 55–90 files



\*\*Detection:\*\*

\- 50+ GetObject calls from same IP in 120 seconds

\- Higher severity for external IPs



\*\*MITRE:\*\* T1530 - Data from Cloud Storage



---



\## 4. Crypto Mining

\*\*File:\*\* `log-generator/attack\_scenarios/crypto\_mining.py`



Simulates an attacker using your cloud to mine cryptocurrency.



\*\*How it works:\*\*

\- Launches 5–15 GPU instances

\- Abuses Lambda functions at scale



\*\*Detection:\*\*

\- GPU instance type in RunInstances call

\- 15+ Lambda invocations in 30 seconds



\*\*MITRE:\*\* T1496 - Resource Hijacking

```



---

