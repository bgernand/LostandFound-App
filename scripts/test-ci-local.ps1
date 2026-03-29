$ErrorActionPreference = "Stop"

$image = if ($env:CI_DOCKER_IMAGE) { $env:CI_DOCKER_IMAGE } else { "debian:13" }
$workspace = "/workspace"

docker run --rm `
  -v "${PWD}:${workspace}" `
  -w $workspace `
  -e "CI=true" `
  -e "PYTHONPATH=$workspace" `
  -e "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true" `
  -e "SECRET_KEY=test-ci-secret" `
  -e "BASE_URL=https://ci.example" `
  $image `
  bash /workspace/scripts/test-ci-in-container.sh
