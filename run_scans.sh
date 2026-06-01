#!/usr/bin/env bash
set -euo pipefail

# Simple helper to scan all techniques currently in techniques/ against a target repo.
# Usage: ./run_scans.sh /path/to/repo [provider] [model]
# Defaults: provider=openai (requires OPENAI_API_KEY), model=gpt-4o-mini.

REPO_PATH="${1:-}"
PROVIDER="${2:-openai}"
MODEL="${3:-gpt-4o-mini}"

if [[ -z "${REPO_PATH}" ]]; then
  echo "usage: $0 /path/to/repo [provider] [model]" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA="${ROOT_DIR}/schemas/technique.schema.json"
SAF_MCP="${ROOT_DIR}/saf-mcp"
TECH_DIR="${ROOT_DIR}/techniques"

if [[ ! -f "${SCHEMA}" ]]; then
  echo "schema not found at ${SCHEMA}" >&2
  exit 1
fi

mkdir -p "${ROOT_DIR}/scan_outputs"

for yaml in "${TECH_DIR}"/T*.yaml; do
  base="$(basename "${yaml}" .yaml)"
  echo "=== Scanning ${base} ==="
  out="${ROOT_DIR}/scan_outputs/${base}.json"
  err_log="${ROOT_DIR}/scan_outputs/${base}.err"
  if ! cargo run -p cli -- \
        --provider "${PROVIDER}" \
        --model-name "${MODEL}" \
        --schema "${SCHEMA}" \
        --saf-mcp "${SAF_MCP}" \
        "${base}" \
        --repo "${REPO_PATH}" \
        --json \
        --llm-review \
        > "${out}" 2> "${err_log}"; then
    echo "Scan for ${base} failed; writing error to ${out} and ${err_log}. Continuing..." >&2
    msg=$(tr '\n' ' ' < "${err_log}" | sed 's/"/\\"/g')
    echo "{\"technique\":\"${base}\",\"error\":\"${msg}\"}" > "${out}"
  fi
done

echo "Scan results stored in ${ROOT_DIR}/scan_outputs/"
