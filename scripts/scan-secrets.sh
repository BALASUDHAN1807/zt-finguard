#!/usr/bin/env bash
# Exposed-credential check for the repository: fails if a private key, a password-like assignment,
# a JWT or a cloud access key is committed. (Image layers are scanned by Trivy: make scan.)
set -uo pipefail
cd "$(dirname "$0")/.."
files=$(git ls-files 2>/dev/null || find . -type f -not -path './.git/*')
hits=$(echo "$files" | grep -vE '\.(png|jpg|pdf|pkl|joblib)$|^tests/|^docs/' | xargs -r grep -nIE \
  -e '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----' \
  -e 'AKIA[0-9A-Z]{16}' \
  -e 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' \
  -e '(password|passwd|secret|api_key|token)[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9!@#$%^&*_+=-]{8,}["'"'"']' \
  2>/dev/null | grep -vE 'getenv|environ|_FILE|read_secret|example|placeholder|Field\(|scan-secrets' || true)
if [[ -n "$hits" ]]; then echo "$hits"; echo "[secrets] possible credentials committed - remove and rotate them"; exit 1; fi
echo "[secrets] no credentials found in tracked files"
