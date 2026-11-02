#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
python3 tests/check_sources.py
test -z "$(gofmt -l cmd internal main.go)"
go test -race ./...
mkdir -p .tools
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o .tools/kam .
python3 tests/prepare_envtest.py
python3 tests/run_controller_api.py
python3 tests/run_auth_api.py

if [[ "${RUN_CHART_VALIDATION:-0}" == "1" ]]; then
  export HELM_BINARY="${HELM_BINARY:-$(python3 tests/prepare_helm.py)}"
  python3 tests/validate_local_chart.py
  KAM_PACKAGE_MODE=helm python3 tests/run_auth_api.py
fi
