#!/bin/bash
echo ">>> Bootstrapping AWS resources..."

AWS_CMD="aws --endpoint-url=http://localhost:4566 --region us-east-1 --no-cli-pager --output json"

# Create S3 buckets
echo ">>> Creating S3 buckets..."
$AWS_CMD s3 mb s3://company-data-prod
$AWS_CMD s3 mb s3://company-logs
$AWS_CMD s3 mb s3://company-secrets

# Create IAM users
echo ">>> Creating IAM users..."
$AWS_CMD iam create-user --user-name regular-user-alice
$AWS_CMD iam create-user --user-name regular-user-bob
$AWS_CMD iam create-user --user-name admin-user-carlos

# Create SNS topic for alerts
echo ">>> Creating SNS topic..."
$AWS_CMD sns create-topic --name threat-alerts

# Create SQS queue
echo ">>> Creating SQS queue..."
$AWS_CMD sqs create-queue --queue-name cloud-events

echo "✅ All AWS resources created!"
```

Save and close, then:
```
git add localstack\init-aws.sh
```
```
git commit -m "infra(localstack): add bootstrap script to create fake AWS resources"
```
```
git push