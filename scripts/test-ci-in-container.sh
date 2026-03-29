#!/usr/bin/env bash
set -euo pipefail

apt-get update
apt-get install -y --no-install-recommends python3 python3-venv ca-certificates
rm -rf /var/lib/apt/lists/*

python3 -m venv .venv
. .venv/bin/activate

pip install --upgrade pip
pip install -r requirements-dev.txt

python3 -c "from lfapp.main import create_app; app=create_app({'SECRET_KEY':'test-ci-secret','BASE_URL':'https://ci.example'}); print(app.name)"
pytest -q
ruff check lfapp tests app.py
