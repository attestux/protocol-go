#!/usr/bin/env bash
set -euo pipefail

go test -race ./...
go vet ./...
go tool staticcheck ./...
go tool govulncheck ./...

unformatted="$(gofmt -l .)"
if [[ -n "${unformatted}" ]]; then
	echo "gofmt needed:" >&2
	echo "${unformatted}" >&2
	exit 1
fi
