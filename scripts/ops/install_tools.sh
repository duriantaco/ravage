#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Install or build Ravage external tool runtime dependencies.

Usage:
  scripts/install_tools.sh [--execute] [--method auto|docker|apt|brew|manual] [--image IMAGE] [--no-cache] [--no-check]

By default this prints the install plan only. Pass --execute to run the
download/build/install commands. After the install step, the script runs
`ravage tools check` with repo-local tool paths and state directories.

Examples:
  scripts/install_tools.sh
  scripts/install_tools.sh --execute
  scripts/install_tools.sh --method docker --execute
  scripts/install_tools.sh --method apt --execute --no-check
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PATH="$repo_root/.tools/bin:$repo_root/.tools/go-root/bin:$PATH"
export HOME="$repo_root/.tools/state/home"
export XDG_CONFIG_HOME="$repo_root/.tools/state/config"
export XDG_CACHE_HOME="$repo_root/.tools/state/cache"
export PYTHONPATH="$repo_root/packages/ravage/src:$repo_root/packages/schemas/src${PYTHONPATH:+:$PYTHONPATH}"
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"

run_check=true
install_args=()
for arg in "$@"; do
  if [[ "$arg" == "--no-check" ]]; then
    run_check=false
  else
    install_args+=("$arg")
  fi
done

ravage_cmd=()
if [[ -x "$repo_root/.venv/bin/python" ]]; then
  ravage_cmd=("$repo_root/.venv/bin/python" -m ravage)
elif command -v ravage >/dev/null 2>&1; then
  ravage_cmd=(ravage)
elif command -v python3 >/dev/null 2>&1; then
  ravage_cmd=(python3 -m ravage)
else
  echo "Could not find ravage, .venv/bin/python, or python3." >&2
  echo "Run scripts/bootstrap.sh first, or install Ravage into the current environment." >&2
  exit 127
fi

"${ravage_cmd[@]}" tools install "${install_args[@]}"

if [[ "$run_check" == true ]]; then
  echo
  "${ravage_cmd[@]}" tools check
fi
