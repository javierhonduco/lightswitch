#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if ! command -v yaml2obj >/dev/null 2>&1; then
  echo "yaml2obj not found; run this script inside 'nix develop'." >&2
  exit 1
fi

for yaml in "$script_dir"/*.yaml; do
  yaml2obj "$yaml" -o "${yaml%.yaml}.elf"
done
