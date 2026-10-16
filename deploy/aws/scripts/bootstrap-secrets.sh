#!/usr/bin/env bash
# Puts madAuth's secrets into the Parameter Store as SecureString parameters, once per deployment:
#   scripts/bootstrap-secrets.sh [path]          (default path: /madauth)
# It creates WEBHOOK_SECRET if it doesn't exist yet, after asking (never with WEBHOOK_AUTH=aws-iam, for a receiver whose Function URL
# has AWS_IAM auth: webhookFunctionArn in cdk.json), and asks for GOOGLE_CLIENT_SECRET
# (leave it empty if you only use Google One Tap / FedCM) and GITHUB_CLIENT_SECRET (empty without GitHub sign-in). The values are never printed and never passed on a
# command line (other processes can read those); they reach the AWS CLI through a file only you can read.
# Uses the AWS CLI's current credentials and region (aws configure / aws sso login, AWS_REGION).
set -euo pipefail

path="${1:-/madauth}"
path="/${path#/}"
path="${path%/}"

exists() {
  aws ssm get-parameter --name "$path/$1" --query Parameter.Name --output text >/dev/null 2>&1
}

# put NAME reads the value from standard input.
put() {
  local input
  input="$(mktemp)"
  chmod 600 "$input"
  python3 -c 'import json, sys; print(json.dumps({"Name": sys.argv[1], "Type": "SecureString", "Overwrite": True, "Value": sys.stdin.read()}))' \
    "$path/$1" > "$input"
  aws ssm put-parameter --cli-input-json "file://$input" >/dev/null
  rm -f "$input"
  echo "Stored $path/$1"
}

# madAuth's keys are in AWS KMS, which the template creates; a signing key from before stops the deploy.
if exists MADAUTH_SIGNING_KEY; then
  echo "$path/MADAUTH_SIGNING_KEY is from a template before madAuth 0.6, which kept the keys here. They are in AWS KMS now,"
  echo "and the deploy fails while it exists. Deleting it signs every user out: aws ssm delete-parameter --name $path/MADAUTH_SIGNING_KEY"
fi

# With AWS IAM the server signs its webhook calls with its role, and a webhook secret stops the deploy.
if [[ "${WEBHOOK_AUTH:-}" == "aws-iam" ]]; then
  if exists WEBHOOK_SECRET; then
    echo "$path/WEBHOOK_SECRET exists, but with an AWS_IAM receiver the deploy fails while it does."
    echo "Delete it once the receiver checks the caller: aws ssm delete-parameter --name $path/WEBHOOK_SECRET"
  fi
elif exists WEBHOOK_SECRET; then
  echo "$path/WEBHOOK_SECRET exists, kept."
else
  # Asked, since running the script again for another secret must not bring it back where AWS IAM replaced it.
  read -r -p "Create $path/WEBHOOK_SECRET? Not with a receiver with AWS IAM (webhookFunctionArn in cdk.json). [Y/n] " create
  if [[ ! "$create" =~ ^[Nn] ]]; then
    npx --yes @madauth/server generate-webhook-secret | put WEBHOOK_SECRET
  fi
fi

read -r -s -p "GOOGLE_CLIENT_SECRET (empty to skip): " google_secret
echo
if [[ -n "$google_secret" ]]; then
  printf '%s' "$google_secret" | put GOOGLE_CLIENT_SECRET
fi

read -r -s -p "GITHUB_CLIENT_SECRET (empty to skip): " github_secret
echo
if [[ -n "$github_secret" ]]; then
  printf '%s' "$github_secret" | put GITHUB_CLIENT_SECRET
fi
