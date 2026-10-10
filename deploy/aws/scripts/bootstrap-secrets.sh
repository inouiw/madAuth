#!/usr/bin/env bash
# Puts madAuth's secrets into the Parameter Store as SecureString parameters, once per deployment:
#   scripts/bootstrap-secrets.sh [path]          (default path: /madauth)
# It creates MADAUTH_SIGNING_KEY and WEBHOOK_SECRET if they don't exist yet, and asks for GOOGLE_CLIENT_SECRET
# (leave it empty if you only use Google One Tap / FedCM). The values are never printed and never passed on a
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

if exists MADAUTH_SIGNING_KEY; then
  echo "$path/MADAUTH_SIGNING_KEY exists, kept. (Replacing it signs every user out.)"
else
  npx --yes @madauth/server generate-key | put MADAUTH_SIGNING_KEY
fi

if exists WEBHOOK_SECRET; then
  echo "$path/WEBHOOK_SECRET exists, kept."
else
  npx --yes @madauth/server generate-webhook-secret | put WEBHOOK_SECRET
fi

read -r -s -p "GOOGLE_CLIENT_SECRET (empty to skip): " google_secret
echo
if [[ -n "$google_secret" ]]; then
  printf '%s' "$google_secret" | put GOOGLE_CLIENT_SECRET
fi
