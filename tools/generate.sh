#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 || ( $# -eq 1 && $1 != --check ) ]]; then
	echo "usage: $0 [--check]" >&2
	exit 2
fi

protoc_gen_go="$(go tool -n protoc-gen-go)"
module_path="$(go list -m -f '{{.Path}}')"
generated_dir="$(mktemp -d .generate.XXXXXX)"
delete_tempfiles() {
	rm -rf "${generated_dir}"
}
trap delete_tempfiles EXIT
protoc \
	"--plugin=protoc-gen-go=${protoc_gen_go}" \
	--proto_path=protocol/proto \
	"--go_out=${generated_dir}" \
	--go_opt=paths=source_relative \
	"--go_opt=Mattestux/v1/wire.proto=${module_path}/attestux/v1;attestuxv1" \
	"--go_opt=Mattestux/v1/report.proto=${module_path}/attestux/v1;attestuxv1" \
	protocol/proto/attestux/v1/wire.proto \
	protocol/proto/attestux/v1/report.proto
if [[ ${1:-} == --check ]]; then
	diff -ru attestux "${generated_dir}/attestux"
else
	mkdir -p attestux/v1
	cp "${generated_dir}/attestux/v1/"*.pb.go attestux/v1/
fi
