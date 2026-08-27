#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [output-dir]" >&2
  exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
src_dir="$script_dir/src"
out_dir=${1:-"$script_dir/../../target/testprogs"}
bin_dir="$out_dir/bin"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/lightswitch-testprogs.XXXXXX")

cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

missing=()
for tool in gcc g++ clang go ocamlopt; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing+=("$tool")
  fi
done

if (( ${#missing[@]} > 0 )); then
  printf 'missing required test fixture build tools:' >&2
  printf ' %s' "${missing[@]}" >&2
  printf '\n' >&2
  exit 1
fi

gcc -O1 "$src_dir/main.cpp" -o "$tmp_dir/main_cpp_gcc_O1"
gcc -O2 "$src_dir/main.cpp" -o "$tmp_dir/main_cpp_gcc_O2"
gcc -O3 "$src_dir/main.cpp" -o "$tmp_dir/main_cpp_gcc_O3"

clang -O1 -fomit-frame-pointer "$src_dir/main.cpp" -o "$tmp_dir/main_cpp_clang_O1"
clang -O2 -fomit-frame-pointer "$src_dir/main.cpp" -o "$tmp_dir/main_cpp_clang_O2"
clang -O3 -fomit-frame-pointer "$src_dir/main.cpp" -o "$tmp_dir/main_cpp_clang_O3"

clang -O3 -fno-omit-frame-pointer "$src_dir/main.cpp" -o "$tmp_dir/main_cpp_clang_no_omit_fp_O3"
clang -O1 -fomit-frame-pointer -fasynchronous-unwind-tables "$src_dir/large_stack_frame.cpp" -o "$tmp_dir/large_stack_frame"
clang -O2 "$src_dir/vdso_clock.cpp" -o "$tmp_dir/vdso_clock"

case "$(uname -m)" in
  aarch64|arm64)
    clang -O3 -mbranch-protection=pac-ret "$src_dir/main.cpp" -o "$tmp_dir/main_cpp_clang_pac"
    ;;
esac

(
  export HOME="${HOME:-$tmp_dir}"
  cd "$src_dir/go"
  go build -o "$tmp_dir/main_go" main.go
  CGO_ENABLED=0 go build -ldflags "-w -s" -o "$tmp_dir/main_go_stripped" main.go
  CGO_ENABLED=0 go build -o "$tmp_dir/main_go_static" main.go
)

(
  ocaml_build_dir="$tmp_dir/ocaml"
  mkdir -p "$ocaml_build_dir"
  cp "$src_dir/ocaml/main.ml" "$ocaml_build_dir"
  cd "$ocaml_build_dir"
  ocamlopt main.ml -o "$tmp_dir/main_ocaml"
)

mkdir -p "$bin_dir"
cp "$tmp_dir"/main_cpp_gcc_O1 "$bin_dir"
cp "$tmp_dir"/main_cpp_gcc_O2 "$bin_dir"
cp "$tmp_dir"/main_cpp_gcc_O3 "$bin_dir"
cp "$tmp_dir"/main_cpp_clang_O1 "$bin_dir"
cp "$tmp_dir"/main_cpp_clang_O2 "$bin_dir"
cp "$tmp_dir"/main_cpp_clang_O3 "$bin_dir"
cp "$tmp_dir"/main_cpp_clang_no_omit_fp_O3 "$bin_dir"
cp "$tmp_dir"/large_stack_frame "$bin_dir"
cp "$tmp_dir"/vdso_clock "$bin_dir"
cp "$tmp_dir"/main_go "$bin_dir"
cp "$tmp_dir"/main_go_stripped "$bin_dir"
cp "$tmp_dir"/main_go_static "$bin_dir"
cp "$tmp_dir"/main_ocaml "$bin_dir"

if [[ -f "$tmp_dir/main_cpp_clang_pac" ]]; then
  cp "$tmp_dir"/main_cpp_clang_pac "$bin_dir"
fi
