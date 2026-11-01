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
