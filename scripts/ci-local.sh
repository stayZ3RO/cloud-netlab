#!/usr/bin/env bash
# Run the same IaC and pytest checks as ci.yml, locally (no gitleaks or Forgejo checks). No AWS credentials required.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if command -v tofu >/dev/null 2>&1; then
  TF=tofu
elif command -v terraform >/dev/null 2>&1; then
  TF=terraform
else
  echo "ERROR: neither 'tofu' nor 'terraform' is installed." >&2
  exit 1
fi

echo "==> IaC: $TF fmt -check"
$TF fmt -check -recursive iac

echo "==> IaC: validate environments/dev"
( cd iac/environments/dev && $TF init -backend=false -input=false >/dev/null && $TF validate )

echo "==> Tool: pytest"
(
  cd tools/net-drift-check
  # Use an isolated venv so the local gate works without a system pip.
  if [ ! -d .venv ]; then python3 -m venv .venv; fi
  # shellcheck disable=SC1091
  . .venv/bin/activate
  python -m pip install -q -r requirements.txt
  python -m pytest -q
)

echo "==> All checks passed."
