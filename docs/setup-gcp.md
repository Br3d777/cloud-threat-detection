\# ☁️ Deploying on Google Cloud Platform



\## Why GCP?

\- UPI / Google Pay accepted in India

\- $300 free credits for 90 days on new accounts

\- No debit card needed



---



\## Step 1: Create a GCP Account

1\. Go to https://cloud.google.com

2\. Click \*\*Get started for free\*\*

3\. Select \*\*India\*\* as your country

4\. Choose \*\*UPI\*\* as payment method

5\. Complete ₹1 verification — refunded immediately

6\. You get \*\*$300 free credits\*\*



---



\## Step 2: Install the GCP CLI

```bash

\# Download from:

\# https://cloud.google.com/sdk/docs/install

gcloud --version

```



\## Step 3: Authenticate

```bash

gcloud auth login

gcloud auth application-default login

```



\## Step 4: Create a Project

```bash

gcloud projects create cloud-threat-detection

gcloud config set project cloud-threat-detection

```



\## Step 5: Run Setup Script

```bash

chmod +x gcp/setup\_gcp.sh

./gcp/setup\_gcp.sh YOUR\_PROJECT\_ID

```



\## Step 6: Configure .env

```

GCP\_PROJECT\_ID=your-project-id

GCP\_REGION=asia-south1

```



\## Step 7: Run Against Real GCP Logs

```bash

python gcp/cloud\_logging\_adapter.py --project YOUR\_PROJECT\_ID

```



---



\## Cost Estimate

Everything used in this project falls within GCP's free tier.

Total cost: $0

```



---



