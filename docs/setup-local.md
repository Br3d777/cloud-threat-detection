\# 💻 Local Development Setup



\## Prerequisites

\- Python 3.11+

\- Docker Desktop

\- Git



---



\## Step 1: Clone the repo

```bash

git clone https://github.com/Br3d777/cloud-threat-detection.git

cd cloud-threat-detection

```



\## Step 2: Copy config

```bash

cp .env.example .env

```



\## Step 3: Start everything

```bash

docker-compose up --build

```



This starts:

\- LocalStack (fake AWS)

\- Log Generator (simulates attacks)

\- Detection Engine (detects threats)

\- Incident Responder (auto-responds)

\- Dashboard (live UI at http://localhost:8080)



---



\## Step 4: Trigger attacks manually

```bash

\# Run all scenarios

python log-generator/generator.py --scenario all



\# Run one specific scenario

python log-generator/generator.py --scenario brute\_force

python log-generator/generator.py --scenario privilege\_escalation

python log-generator/generator.py --scenario data\_exfiltration

python log-generator/generator.py --scenario crypto\_mining

```



---



\## Step 5: Run tests

```bash

pip install -r requirements.txt

pytest tests/ -v

```



---



\## Stopping the project

```bash

docker-compose down

```

```



---

