#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Create or refresh Ravage's source-checkout virtual environment.

Usage:
  scripts/bootstrap.sh [--dev] [--browser] [--install-browser]

Options:
  --dev              Install the repository development dependency group.
  --browser          Install the optional Playwright Python package only.
  --install-browser  Also download Playwright Chromium; implies --browser.
  -h, --help         Show this help without changing the environment.

The default install is deliberately lean: it installs the editable Ravage and
schema packages, but not Playwright, Chromium, Docker images, or scanners.
External tools remain an explicit `ravage tools install --execute` step.
EOF
}

with_dev=false
with_browser=false
install_browser=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dev)
      with_dev=true
      ;;
    --browser)
      with_browser=true
      ;;
    --install-browser)
      with_browser=true
      install_browser=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown bootstrap option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV_INPUT="${RAVAGE_VENV:-"$ROOT/.venv"}"
PYTHON_BIN="${RAVAGE_PYTHON:-}"

python_is_supported() {
  "$1" -c 'import sys; raise SystemExit(0 if (3, 12) <= sys.version_info < (3, 13) else 1)' \
    >/dev/null 2>&1
}

python_version() {
  "$1" -c 'import sys; print(".".join(str(part) for part in sys.version_info[:3]))' \
    2>/dev/null || printf 'unknown'
}

resolve_command() {
  local requested="$1"
  if [[ "$requested" == */* ]]; then
    [[ -x "$requested" ]] || return 1
    printf '%s\n' "$requested"
    return 0
  fi
  command -v "$requested"
}

find_uv() {
  if command -v uv >/dev/null 2>&1; then
    command -v uv
    return 0
  fi
  if [[ -x "$ROOT/.venv/bin/uv" ]]; then
    printf '%s\n' "$ROOT/.venv/bin/uv"
    return 0
  fi
  return 1
}

uv_python_312() {
  local uv_bin="$1"
  local candidate
  candidate="$("$uv_bin" python find 3.12 \
    --managed-python \
    --no-python-downloads \
    --no-project \
    --no-config \
    2>/dev/null || true)"
  [[ -n "$candidate" && -x "$candidate" ]] || return 1
  python_is_supported "$candidate" || return 1
  printf '%s\n' "$candidate"
}

print_python_guidance() {
  local discovered="${1:-}"
  if [[ -n "$discovered" ]]; then
    echo "error: Python >=3.12,<3.13 is required; found $discovered" >&2
  else
    echo "error: Python >=3.12,<3.13 was not found" >&2
  fi
  echo "Install it with \`uv python install 3.12\`, then rerun scripts/bootstrap.sh." >&2
  echo "You may also set RAVAGE_PYTHON to an existing Python 3.12 executable." >&2
}

if [[ -n "$PYTHON_BIN" ]]; then
  if ! PYTHON_BIN="$(resolve_command "$PYTHON_BIN")"; then
    echo "error: RAVAGE_PYTHON is not executable: ${RAVAGE_PYTHON}" >&2
    print_python_guidance
    exit 1
  fi
  if ! python_is_supported "$PYTHON_BIN"; then
    print_python_guidance "$(python_version "$PYTHON_BIN")"
    exit 1
  fi
else
  if command -v python3.12 >/dev/null 2>&1 \
    && python_is_supported "$(command -v python3.12)"; then
    PYTHON_BIN="$(command -v python3.12)"
  elif command -v python3 >/dev/null 2>&1 \
    && python_is_supported "$(command -v python3)"; then
    PYTHON_BIN="$(command -v python3)"
  else
    uv_bin="$(find_uv || true)"
    if [[ -n "$uv_bin" ]]; then
      PYTHON_BIN="$(uv_python_312 "$uv_bin" || true)"
      if [[ -n "$PYTHON_BIN" ]]; then
        echo "[bootstrap] using uv-managed Python 3.12: $PYTHON_BIN"
      fi
    fi
  fi
  if [[ -z "$PYTHON_BIN" ]]; then
    discovered=""
    if command -v python3 >/dev/null 2>&1; then
      discovered="$(python_version "$(command -v python3)")"
    fi
    print_python_guidance "$discovered"
    exit 1
  fi
  if ! python_is_supported "$PYTHON_BIN"; then
    print_python_guidance "$(python_version "$PYTHON_BIN")"
    exit 1
  fi
fi

absolute_path() {
  "$PYTHON_BIN" -c \
    'import os, sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' \
    "$1"
}

canonical_path() {
  "$PYTHON_BIN" -c \
    'import pathlib, sys; print(pathlib.Path(sys.argv[1]).expanduser().resolve(strict=False))' \
    "$1"
}

path_is_same_or_ancestor() {
  local possible_ancestor="$1"
  local path="$2"
  [[ "$path" == "$possible_ancestor" || "$path" == "$possible_ancestor"/* ]]
}

VENV="$(absolute_path "$VENV_INPUT")"
VENV_CANONICAL="$(canonical_path "$VENV")"
ROOT_CANONICAL="$(canonical_path "$ROOT")"
USER_HOME_CANONICAL="$(canonical_path "${HOME:-$ROOT}")"

if [[ -z "$VENV_CANONICAL" || "$VENV_CANONICAL" == "/" ]] \
  || path_is_same_or_ancestor "$VENV_CANONICAL" "$ROOT_CANONICAL" \
  || path_is_same_or_ancestor "$VENV_CANONICAL" "$USER_HOME_CANONICAL"; then
  echo "error: refusing broad virtualenv target: $VENV" >&2
  echo "Choose a dedicated virtualenv directory, such as $ROOT/.venv." >&2
  exit 1
fi

if [[ -L "$VENV" ]]; then
  echo "error: virtualenv target cannot be a symlink: $VENV" >&2
  exit 1
fi
if [[ -e "$VENV" && ! -d "$VENV" ]]; then
  echo "error: virtualenv target is not a directory: $VENV" >&2
  exit 1
fi
if [[ -d "$VENV" && ! -f "$VENV/pyvenv.cfg" ]]; then
  echo "error: refusing to replace non-venv directory: $VENV" >&2
  echo "Move it aside or choose a different RAVAGE_VENV path." >&2
  exit 1
fi

venv_is_current() {
  [[ -f "$VENV/pyvenv.cfg" && -x "$VENV/bin/python" && -f "$VENV/bin/activate" ]] \
    || return 1
  python_is_supported "$VENV/bin/python" || return 1
  grep -Fq "VIRTUAL_ENV=$VENV" "$VENV/bin/activate" \
    || grep -Fq "VIRTUAL_ENV='$VENV'" "$VENV/bin/activate" \
    || grep -Fq "VIRTUAL_ENV=\"$VENV\"" "$VENV/bin/activate"
}

recreate_venv=false
if [[ ! -d "$VENV" ]]; then
  recreate_venv=true
elif ! venv_is_current; then
  echo "[bootstrap] detected a stale or damaged virtualenv: $VENV"
  recreate_venv=true
fi

VENV_CREATOR="$PYTHON_BIN"
python_command_path="$(absolute_path "$PYTHON_BIN")"
if path_is_same_or_ancestor "$VENV_CANONICAL" "$(canonical_path "$python_command_path")"; then
  base_python="$("$PYTHON_BIN" -c 'import sys; print(getattr(sys, "_base_executable", "") or sys.executable)')"
  if [[ -x "$base_python" ]] && python_is_supported "$base_python"; then
    VENV_CREATOR="$base_python"
  elif [[ "$recreate_venv" == true ]]; then
    echo "error: the selected Python is inside the virtualenv that must be recreated" >&2
    echo "Deactivate it or set RAVAGE_PYTHON to an external Python 3.12 executable." >&2
    exit 1
  fi
fi

if [[ "$recreate_venv" == true ]]; then
  if [[ -d "$VENV" ]]; then
    if [[ ! -f "$VENV/pyvenv.cfg" ]]; then
      echo "error: refusing to delete a directory without pyvenv.cfg: $VENV" >&2
      exit 1
    fi
    rm -rf -- "$VENV"
  fi
  "$VENV_CREATOR" -m venv "$VENV"
fi

cd "$ROOT"
export PIP_CACHE_DIR="${PIP_CACHE_DIR:-"$ROOT/.tools/state/pip-cache"}"
export PIP_DISABLE_PIP_VERSION_CHECK=1
mkdir -p "$PIP_CACHE_DIR"

"$VENV/bin/python" -m ensurepip --upgrade >/dev/null

ravage_editable="$ROOT/packages/ravage"
if [[ "$with_browser" == true ]]; then
  ravage_editable="${ravage_editable}[browser]"
fi

echo "[bootstrap] installing editable Ravage packages"
"$VENV/bin/python" -m pip install -q \
  -e "$ROOT/packages/schemas" \
  -e "$ravage_editable"

if [[ "$with_dev" == true ]]; then
  dev_dependencies=()
  while IFS= read -r dependency; do
    [[ -n "$dependency" ]] && dev_dependencies+=("$dependency")
  done < <(
    "$VENV/bin/python" -c \
      'import pathlib, sys, tomllib
data = tomllib.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
items = data.get("dependency-groups", {}).get("dev", [])
if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
    raise SystemExit("invalid dependency-groups.dev in pyproject.toml")
print("\n".join(items))' \
      "$ROOT/pyproject.toml"
  )
  if [[ ${#dev_dependencies[@]} -eq 0 ]]; then
    echo "error: dependency-groups.dev is empty" >&2
    exit 1
  fi
  echo "[bootstrap] installing development dependencies"
  "$VENV/bin/python" -m pip install -q "${dev_dependencies[@]}"
fi

if [[ "$install_browser" == true ]]; then
  echo "[bootstrap] downloading Playwright Chromium (explicit --install-browser request)"
  "$VENV/bin/python" -m playwright install chromium
elif [[ "$with_browser" == true ]]; then
  echo "[bootstrap] Playwright Python support installed; Chromium was not downloaded."
  echo "[bootstrap] Download it later with: $VENV/bin/python -m playwright install chromium"
fi

echo "[bootstrap] running core self-check"
"$VENV/bin/python" -m ravage --version
"$VENV/bin/ravage" --help >/dev/null

echo
echo "[bootstrap] Ravage is ready."
echo "Next: source \"$VENV/bin/activate\" && ravage init http://127.0.0.1:3000"
