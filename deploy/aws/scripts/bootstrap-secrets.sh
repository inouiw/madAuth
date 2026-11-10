#!/usr/bin/env bash
# Puts madAuth's secrets into the Parameter Store as SecureString parameters, once per deployment:
#   scripts/bootstrap-secrets.sh [path]          (default path: /madauth)
# It creates WEBHOOK_SECRET if it doesn't exist yet, only if you answer yes: the template signs the webhook calls with an
# Ed25519 key in AWS KMS (v1a), which receivers check with its public key alone, so a shared secret is only for a receiver
# that checks v1 signatures (never with WEBHOOK_AUTH=aws-iam, for a receiver whose Function URL has AWS_IAM auth:
# webhookFunctionArn in cdk.json). The value is never printed and never passed on a command line
# (other processes can read those); it reaches the AWS CLI through a file only you can read. Google and GitHub
# are no secrets of the deployment any more: an admin adds them as providers (see "Providers" in docs/server.md).
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
  # Asked, and no by default: the webhook key in KMS signs the calls (v1a), and the receiver needs no secret.
  echo "The webhook calls are signed with an Ed25519 key in AWS KMS (v1a): a receiver checks them with the public key"
  echo "from <issuer>/.well-known/webhook-keys.json, and needs no secret."
  read -r -p "Create $path/WEBHOOK_SECRET anyway, for a receiver that checks only v1 signatures with a shared secret? Not with AWS IAM. [y/N] " create
  if [[ "$create" =~ ^[Yy] ]]; then
    npx --yes @madauth/server generate-webhook-secret | put WEBHOOK_SECRET
  fi
fi

# Google and GitHub from a template before madAuth 0.7: their client IDs are gone from cdk.json, so these are read by nobody.
for name in GOOGLE_CLIENT_SECRET GITHUB_CLIENT_SECRET; do
  if exists "$name"; then
    echo "$path/$name is from a template before madAuth 0.7 and no longer used: add the provider in the admin API, then delete it: aws ssm delete-parameter --name $path/$name"
  fi
done
