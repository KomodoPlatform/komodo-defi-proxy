#!/bin/bash
set -euo pipefail

curl --silent --fail --max-time 10 \
  --header "Content-Type: application/json" \
  --data '{"userpass":"testpass","method":"version"}' \
  http://127.0.0.1:8967 >/dev/null
