$ErrorActionPreference = "Stop"

$image = if ($env:CI_DOCKER_IMAGE) { $env:CI_DOCKER_IMAGE } else { "debian:13" }
$workspace = "/workspace"

docker run --rm -it `
  -v "${PWD}:${workspace}" `
  -w $workspace `
  -e "PYTHONPATH=$workspace" `
  -e "SECRET_KEY=test-ci-secret" `
  -e "BASE_URL=https://ci.example" `
  $image `
  bash -lc @'
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
'@
