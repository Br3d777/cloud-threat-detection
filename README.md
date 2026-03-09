# \# ☁️ Cloud Threat Detection \& Incident Response System

# 

# <div align="center">

# 

# !\[Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge\&logo=python\&logoColor=white)

# !\[Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge\&logo=docker\&logoColor=white)

# !\[GCP](https://img.shields.io/badge/Google\_Cloud-Supported-4285F4?style=for-the-badge\&logo=googlecloud\&logoColor=white)

# !\[License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

# !\[CI](https://github.com/Br3d777/cloud-threat-detection/actions/workflows/tests.yml/badge.svg)

# 

# \*\*A production-grade cloud security system that detects, alerts on, and auto-responds to real-world attack scenarios in real time.\*\*

# 

# </div>

# 

# ---

# 

# \## 🔍 What This Does

# 

# This system monitors cloud infrastructure logs, applies rule-based detection to classify threats, scores their severity, and automatically triggers incident response playbooks — all running locally with one command.

# 

# ---

# 

# \## ⚔️ Attack Scenarios Detected

# 

# | Scenario | Trigger | Severity | MITRE Technique |

# |---|---|---|---|

# | 🔐 Brute Force | 5+ failed logins from same IP in 60s | CRITICAL | T1110 |

# | 👑 Privilege Escalation | Non-admin attaches AdministratorAccess | CRITICAL | T1098 |

# | 📦 Data Exfiltration | 50+ S3 downloads in 120s | CRITICAL | T1530 |

# | ⛏️ Crypto Mining | GPU instance launch or Lambda spike | HIGH | T1496 |

# 

# ---

# 

# \## 🏗️ Architecture

# ```

# Log Generator → Detection Engine → Incident Responder → Dashboard

# &nbsp;    ↓                 ↓                   ↓                ↓

# Simulates         IAM Rules          Isolate User      Live UI at

# attack events     S3 Rules           Notify Team       :8080

# &nbsp;                 Network Rules

# ```

# 

# ---

# 

# \## 🚀 Quick Start

# 

# \*\*Requirements:\*\* Docker Desktop, Python 3.11+

# ```bash

# \# 1. Clone the repo

# git clone https://github.com/Br3d777/cloud-threat-detection.git

# cd cloud-threat-detection

# 

# \# 2. Copy config

# cp .env.example .env

# 

# \# 3. Start everything

# docker-compose up --build

# 

# \# 4. Open the dashboard

# \# Visit http://localhost:8080

# ```

# 

# ---

# 

# \## 📁 Project Structure

# ```

# cloud-threat-detection/

# ├── log-generator/

# │   ├── generator.py               # Simulates cloud events

# │   └── attack\_scenarios/

# │       ├── brute\_force.py

# │       ├── privilege\_escalation.py

# │       ├── data\_exfiltration.py

# │       └── crypto\_mining.py

# │

# ├── detection-engine/

# │   ├── detector.py                # Core detection loop

# │   └── rules/

# │       ├── iam\_rules.py           # Brute force + priv esc

# │       ├── s3\_rules.py            # Data exfiltration

# │       └── network\_rules.py      # Crypto mining

# │

# ├── incident-response/

# │   ├── responder.py               # Alert router

# │   └── playbooks/

# │       ├── isolate\_resource.py   # Lock out compromised user

# │       └── notify\_team.py        # Slack + SNS alerts

# │

# ├── dashboard/

# │   ├── index.html                 # Live threat dashboard

# │   └── api\_server.py             # FastAPI backend

# │

# ├── tests/

# │   └── test\_rules.py             # Unit tests (CI/CD)

# │

# └── docker-compose.yml            # One command to run all

# ```

# 

# ---

# 

# \## 🧪 Running Tests

# ```bash

# pip install -r requirements.txt

# pytest tests/ -v

# ```

# 

# Tests run automatically on every push via GitHub Actions.

# 

# ---

# 

# \## 📊 Severity Scoring

# 

# | Score | Level | Auto-Response |

# |---|---|---|

# | 8–10 | 🔴 CRITICAL | Isolate user + notify team |

# | 5–7 | 🟠 HIGH | Notify team |

# | 3–4 | 🟡 MEDIUM | Log and monitor |

# | 1–2 | 🔵 LOW | Log only |

# 

# ---

# 

# \## ☁️ GCP Deployment

# 

# Supports real Google Cloud deployment via the GCP adapter.

# GCP accepts UPI payments — see \[docs/setup-gcp.md](docs/setup-gcp.md).

# 

# ---

# 

# \## 📚 References

# 

# \- \[MITRE ATT\&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)

# \- \[AWS CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)

# \- \[LocalStack Documentation](https://docs.localstack.cloud/)

# 

# ---

# 

# \## 📄 License

# 

# MIT

