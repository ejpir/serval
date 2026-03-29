#!/usr/bin/env bash
set -euo pipefail

ZIG_BIN_DEFAULT="/usr/local/zig-x86_64-linux-0.16.0-dev.2821+3edaef9e0/zig"
OUTPUT_DIR="zig-out/api-docs"
LOCAL_CACHE_DIR="/tmp/serval-docs-zig-cache"
GLOBAL_CACHE_DIR="/tmp/serval-docs-zig-global-cache"
DRY_RUN=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Generate Zig HTML API docs for each module entrypoint and create a landing page.

Options:
  --zig <path>         Zig compiler path (default: ${ZIG_BIN_DEFAULT})
  --output-dir <path>  Output base directory (default: ${OUTPUT_DIR})
  --cache-dir <path>   Zig local cache dir (default: ${LOCAL_CACHE_DIR})
  --global-cache-dir <path>
                       Zig global cache dir (default: ${GLOBAL_CACHE_DIR})
  --dry-run            Print actions without generating docs
  -h, --help           Show this help
EOF
}

ZIG_BIN="${ZIG_BIN_DEFAULT}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --zig)
      ZIG_BIN="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --cache-dir)
      LOCAL_CACHE_DIR="$2"
      shift 2
      ;;
    --global-cache-dir)
      GLOBAL_CACHE_DIR="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! -x "$ZIG_BIN" ]]; then
  echo "error: zig binary not executable: $ZIG_BIN" >&2
  exit 1
fi

mapfile -t MODULE_ENTRIES < <(
  {
    [[ -f "serval/mod.zig" ]] && echo "serval/mod.zig"
    for d in serval-*; do
      [[ -d "$d" && -f "$d/mod.zig" ]] || continue
      echo "$d/mod.zig"
    done
  } | sort -u
)

if [[ ${#MODULE_ENTRIES[@]} -eq 0 ]]; then
  echo "error: no module entrypoints found (expected serval*/mod.zig)" >&2
  exit 1
fi

if [[ $DRY_RUN -eq 0 ]]; then
  mkdir -p "$OUTPUT_DIR"
  mkdir -p "$LOCAL_CACHE_DIR" "$GLOBAL_CACHE_DIR"
fi

html_escape() {
  local s="$1"
  s=${s//&/&amp;}
  s=${s//</&lt;}
  s=${s//>/&gt;}
  printf '%s' "$s"
}

LINK_ROWS=()

for entry in "${MODULE_ENTRIES[@]}"; do
  module_dir="${entry%/mod.zig}"
  module_name="${module_dir#./}"
  module_out="${OUTPUT_DIR}/${module_name}"

  echo "module=${module_name} entry=${entry} out=${module_out}"

  if [[ $DRY_RUN -eq 0 ]]; then
    mkdir -p "$module_out"
    "$ZIG_BIN" build-lib "$entry" \
      -fno-emit-bin \
      -femit-docs="$module_out" \
      --cache-dir "$LOCAL_CACHE_DIR" \
      --global-cache-dir "$GLOBAL_CACHE_DIR"
  fi

  LINK_ROWS+=("<li><a href=\"$(html_escape "${module_name}")/index.html\">$(html_escape "${module_name}")</a></li>")
done

if [[ $DRY_RUN -eq 1 ]]; then
  echo "dry-run: skipping landing page generation"
  exit 0
fi

INDEX_PATH="${OUTPUT_DIR}/index.html"
GENERATED_AT="$(date -u +"%Y-%m-%d %H:%M:%SZ")"

{
  echo "<!doctype html>"
  echo "<html lang=\"en\">"
  echo "<head>"
  echo "  <meta charset=\"utf-8\">"
  echo "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
  echo "  <title>Serval API Docs</title>"
  echo "  <style>"
  echo "    :root { color-scheme: light; }"
  echo "    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; line-height: 1.4; }"
  echo "    h1 { margin-bottom: .25rem; }"
  echo "    p.meta { color: #444; margin-top: 0; }"
  echo "    ul { padding-left: 1.2rem; }"
  echo "    li { margin: .3rem 0; }"
  echo "    a { text-decoration: none; }"
  echo "    a:hover { text-decoration: underline; }"
  echo "  </style>"
  echo "</head>"
  echo "<body>"
  echo "  <h1>Serval API Docs</h1>"
  echo "  <p class=\"meta\">Generated ${GENERATED_AT}</p>"
  echo "  <ul>"
  for row in "${LINK_ROWS[@]}"; do
    echo "    ${row}"
  done
  echo "  </ul>"
  echo "</body>"
  echo "</html>"
} > "$INDEX_PATH"

echo "wrote ${INDEX_PATH}"
