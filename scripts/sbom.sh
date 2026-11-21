#!/usr/bin/env bash
# Writes a CycloneDX software bill of materials for a built vajra binary to
# standard output, from the module information Go embeds in the binary.
# Usage: scripts/sbom.sh ./vajra > sbom.json
set -euo pipefail

binary="${1:?usage: scripts/sbom.sh BINARY}"
info="$(go version -m "$binary")"
go_version="$(printf '%s\n' "$info" | awk 'NR==1 {print $2}')"
if command -v sha256sum >/dev/null 2>&1; then
  sha256="$(sha256sum "$binary" | awk '{print $1}')"
else
  sha256="$(shasum -a 256 "$binary" | awk '{print $1}')"
fi

printf '{\n  "bomFormat": "CycloneDX",\n  "specVersion": "1.5",\n  "version": 1,\n'
printf '  "metadata": {\n    "component": {"type": "application", "name": "vajra", "hashes": [{"alg": "SHA-256", "content": "%s"}]},\n' "$sha256"
printf '    "tools": [{"name": "go", "version": "%s"}]\n  },\n' "$go_version"
printf '  "components": ['
# "dep" lines list every module compiled in: path, version, checksum.
printf '%s\n' "$info" | awk '
  $1 == "dep" {
    sum = $4; sub(/^h1:/, "", sum)
    printf "%s\n    {\"type\": \"library\", \"name\": \"%s\", \"version\": \"%s\", \"purl\": \"pkg:golang/%s@%s\", \"hashes\": [{\"alg\": \"SHA-256\", \"content\": \"%s\"}]}", (n++ ? "," : ""), $2, $3, $2, $3, sum
  }'
printf '\n  ]\n}\n'
