#!/usr/bin/env bash
set -euo pipefail

IMAGE="${CI_DOCKER_IMAGE:-debian:13}"
WORKDIR="/workspace"

docker run --rm \
  -v "$PWD:$WORKDIR" \
  -w "$WORKDIR" \
  -e CI="true" \
  -e PYTHONPATH="$WORKDIR" \
  -e FORCE_JAVASCRIPT_ACTIONS_TO_NODE24="true" \
  -e SECRET_KEY="test-ci-secret" \
  -e BASE_URL="https://ci.example" \
  "$IMAGE" \
  bash /workspace/scripts/test-ci-in-container.sh
