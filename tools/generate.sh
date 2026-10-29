#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 || ( $# -eq 1 && $1 != --check ) ]]; then
	echo "usage: $0 [--check]" >&2
	exit 2
fi

protoc_gen_go="$(go tool -n protoc-gen-go)"
generated_dir="$(mktemp -d .generate.XXXXXX)"
delete_tempfiles() {
	rm -rf "${generated_dir}"
}
trap delete_tempfiles EXIT
find protocol/proto -name '*.proto' -exec protoc \
	"--plugin=protoc-gen-go=${protoc_gen_go}" \
	--proto_path=protocol/proto \
	"--go_out=${generated_dir}" \
	--go_opt=paths=source_relative {} +
if [[ ${1:-} == --check ]]; then
	diff -ru attestux "${generated_dir}/attestux"
else
	rm -rf attestux
	mv "${generated_dir}/attestux" .
fi
