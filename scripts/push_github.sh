#!/usr/bin/env bash
# Create a public GitHub repo and push SOC-ify.
# Usage:  GITHUB_TOKEN=<your PAT> bash push_github.sh
set -euo pipefail

REPO_NAME="${1:-soc-ify}"
GITHUB_USER=""
TOKEN="${GITHUB_TOKEN:-}"

if [ -z "$TOKEN" ]; then
  echo "[!] Set GITHUB_TOKEN (a Personal Access Token with 'repo' scope)."
  echo "    Run:  GITHUB_TOKEN=<token> bash push_github.sh"
  exit 1
fi

# Discover the authenticated user (avoids guessing the username)
echo "==> Resolving GitHub user from token"
USER_JSON=$(curl -sS -H "Authorization: token $TOKEN" https://api.github.com/user)
GITHUB_USER=$(echo "$USER_JSON" | python -c "import sys,json;print(json.load(sys.stdin).get('login',''))" 2>/dev/null)
if [ -z "$GITHUB_USER" ]; then
  echo "[!] Could not resolve user from token. Check that the PAT is valid."
  exit 1
fi
echo "    authenticated as: $GITHUB_USER"

echo "==> Creating public repo: $GITHUB_USER/$REPO_NAME"
CREATE=$(curl -sS -X POST -H "Authorization: token $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -d "{\"name\":\"$REPO_NAME\",\"description\":\"SOC-ify: mini SOC on Azure + Elasticsearch 8.12 (Basic-compatible). nginx attack detection, triage, reports, Kibana dashboard.\",\"public\":true}" \
  https://api.github.com/user/repos)
# validate (ignore "already exists" 422)
HTTP_CREATE=$(echo "$CREATE" | python -c "import sys,json
try:
  d=json.load(sys.stdin); print('ok' if ''.join(d.keys()) != 'message' else ('exists' if 'already exists' in d.get('message','') else 'ERR:'+d.get('message','')))
except: print('parse-err')" 2>/dev/null)
echo "    create result: $HTTP_CREATE"

git remote add origin "https://$TOKEN@github.com/$GITHUB_USER/$REPO_NAME.git" 2>/dev/null || \
  git remote set-url origin "https://$TOKEN@github.com/$GITHUB_USER/$REPO_NAME.git"
git remote set-url origin "https://$GITHUB_USER:$TOKEN@github.com/$GITHUB_USER/$REPO_NAME.git"

echo "==> Pushing main"
git push -u origin main
echo "==> Done. Repo at: https://github.com/$GITHUB_USER/$REPO_NAME"
