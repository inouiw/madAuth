#!/usr/bin/env bash
# Puts madAuth's secrets into the Parameter Store as SecureString parameters, once per deployment:
#   scripts/bootstrap-secrets.sh [path]          (default path: /madauth)
# It creates MADAUTH_SIGNING_KEY and WEBHOOK_SECRET if they don't exist yet, and asks for GOOGLE_CLIENT_SECRET
# (leave it empty if you only use Google One Tap / FedCM). The values are never printed or written to disk.
# Uses the AWS CLI's current credentials and region (aws configure / aws sso login, AWS_REGION).
set -euo pipefail

path="${1:-/madauth}"
path="${path%/}"

exists() {
  aws ssm get-parameter --name "$path/$1" --query Parameter.Name --output text >/dev/null 2>&1
}

put() {
  aws ssm put-parameter --name "$path/$1" --type SecureString --value "$2" --overwrite >/dev/null
  echo "Stored $path/$1"
}

if exists MADAUTH_SIGNING_KEY; then
  echo "$path/MADAUTH_SIGNING_KEY exists, kept. (Replacing it signs every user out.)"
else
  put MADAUTH_SIGNING_KEY "$(npx --yes @madauth/server generate-key)"
fi

if exists WEBHOOK_SECRET; then
  echo "$path/WEBHOOK_SECRET exists, kept."
else
  put WEBHOOK_SECRET "$(npx --yes @madauth/server generate-webhook-secret)"
fi

read -r -s -p "GOOGLE_CLIENT_SECRET (empty to skip): " google_secret
echo
if [[ -n "$google_secret" ]]; then
  put GOOGLE_CLIENT_SECRET "$google_secret"
fi
