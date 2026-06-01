# Repository Guidelines

## Project Structure & Inputs
- Rust workspace: `engine/` (analysis core), `cli/` (saf-mcp-scan), `server/` (saf-mcp-analyzer), `schemas/` (JSON Schema helpers), `saf-mcp/` (vendored corpus; keep gitignored), `techniques/` (active specs), `techniques_backup/` (deprioritized specs).
- Technique metadata: canonical table `saf-mcp/README.md`, prioritized list `saf-mcp/techniques/prioritized-techniques.md`, mitigations under `saf-mcp/mitigations/`, per-technique guidance `saf-mcp/techniques/<ID>/README.md`. Prompts must include the per-technique README excerpt; evidence must cite which artifacts were read.

## Build, Test, Run
- Toolchain: stable Rust (`cargo fmt`, `cargo clippy --all-targets --all-features`, `cargo test --all`).
- CLI: `cargo run -p cli -- --provider openai --model-name gpt-4o-mini T1001 --repo <path> --schema $(pwd)/schemas/technique.schema.json --json [--llm-review]`. LLM review reuses the configured OpenAI model/key and is non-fatal on failure.
- MCP server: `cargo run -p server --bin saf-mcp-analyzer`. Config (YAML/JSON) sets provider keys, allowlists, retries/timeouts, and path filters (`include_*`, `exclude_*`, `max_file_bytes`, docs allowed by default; `0` disables size checks).
- Batch scans: `./run_scans.sh` runs all specs under `techniques/`, continuing on failures and writing `scan_outputs/*.json`.

## Workflow & Planning
- Track work in your chosen tracker; keep sequencing/dependencies noted. After every code change, record design decisions, prompts/model settings, filters used, and test commands. Mark status promptly.
- Add new issues to your tracker; note ordering/dependencies when relevant.

## Coding Style & Conventions
- `rustfmt`/`clippy` before commits; prefer explicit error types. IDs: techniques `SAF-T####` (schema enforces `T####` inside specs), mitigations `M-##`, schema files kebab-case under `schemas/`.
- Prompts carry file path/extension/lines plus README excerpt; findings must include evidence (path, line range, snippet) and state artifacts consulted. Avoid inventing findings; keep model temperature at 0.

## Testing Expectations
- Add unit tests beside modules (loader/validator/cache, README/prioritized/mitigation indices, chunking, prompts, adapters, aggregation/status, config). Use fixtures under `tests/fixtures/`; stub model adapters for deterministic outputs. Failures must be clear and user-facing.

## Commit & PR Practices
- DCO sign (`git commit -s`) with scoped subjects (e.g., `engine: add retry adapter`). PRs list commands run and note schema/config changes. Never commit `saf-mcp/` mutations.

## Security & Configuration
- No secrets in git; read provider keys from env/config. Enforce provider allowlist/`allow_remote_providers` before making remote calls. Respect path filters when sending code to models; keep logs free of secrets and large payloads.
