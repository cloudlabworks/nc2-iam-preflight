#!/usr/bin/env bash
# Run nc2-iam-preflight as each test role, in AWS CloudShell, signed in as the operator.
# Usage (from the repo root): bash live-test/run.sh   → writes live-test/results/<role>.json
# Assumes each role with temporary credentials (nothing written to disk), runs the tool, restores the caller.
set -u
ACCT=$(aws sts get-caller-identity --query Account --output text)
mkdir -p live-test/results
for R in nc2test-admin nc2test-guide-policies nc2test-iam-only nc2test-poweruser nc2test-deny-passrole nc2test-bounded nc2test-readonly; do
  C=$(aws sts assume-role --role-arn "arn:aws:iam::$ACCT:role/$R" --role-session-name nc2test --query Credentials --output json) || { echo "$R: assume failed"; continue; }
  ( export AWS_ACCESS_KEY_ID=$(echo "$C" | python3 -c 'import sys,json;print(json.load(sys.stdin)["AccessKeyId"])') \
           AWS_SECRET_ACCESS_KEY=$(echo "$C" | python3 -c 'import sys,json;print(json.load(sys.stdin)["SecretAccessKey"])') \
           AWS_SESSION_TOKEN=$(echo "$C" | python3 -c 'import sys,json;print(json.load(sys.stdin)["SessionToken"])')
    python3 nc2_iam_preflight.py --json aws > "live-test/results/$R.json" 2>&1; echo "$R exit=$?" )
done
# account id out of anything we might publish
sed -i "s/$ACCT/<account-id>/g" live-test/results/*.json
echo done
