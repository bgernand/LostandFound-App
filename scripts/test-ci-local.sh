#!/usr/bin/env bash
set -euo pipefail

IMAGE="${CI_DOCKER_IMAGE:-debian:13}"
WORKDIR="/workspace"

docker run --rm -it \
  -v "$PWD:$WORKDIR" \
  -w "$WORKDIR" \
  -e PYTHONPATH="$WORKDIR" \
  -e SECRET_KEY="test-ci-secret" \
  -e BASE_URL="https://ci.example" \
  "$IMAGE" \
  bash -lc '
    apt-get update &&
    apt-get install -y --no-install-recommends python3 python3-venv ca-certificates &&
    rm -rf /var/lib/apt/lists/* &&
    python3 -m venv .venv &&
    . .venv/bin/activate &&
    pip install --upgrade pip &&
    pip install -r requirements-dev.txt &&
    python3 -c "from lfapp.main import create_app; app=create_app({\"SECRET_KEY\":\"test-ci-secret\",\"BASE_URL\":\"https://ci.example\"}); print(app.name)" &&
    pytest -q &&
    ruff check lfapp tests app.py
  '
