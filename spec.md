SAF‑MCP Static Code Analysis – MCP Integration Spec

1. Overview

This document specifies a system that performs SAF‑MCP–aware static-ish code analysis for a source repository, using LLM code models under the hood, and exposes that capability via an MCP server.

The system has three primary layers:
	1.	SAF‑MCP Analysis Engine (library + CLI) – core logic, technique semantics, repo walking, chunking, and aggregation.
	2.	Model Adapter Layer – abstraction over one or more code‑capable LLM providers (OpenAI, Anthropic, local models).
	3.	MCP Server (saf-mcp-analyzer) – exposes analysis capabilities as tools for MCP‑aware clients (ChatGPT, Claude Desktop, IDE agents).

The analysis engine is the “source of truth” and may be used independently in CI, Git hooks, etc. MCP is a UX/integration surface, not the enforcement point.

⸻

2. Goals
	1.	Provide a reusable, provider‑agnostic SAF‑MCP analysis engine:
	•	Input: technique ID (e.g., T1101), repo path, config.
	•	Output: structured findings with status, evidence, line numbers, and mitigation mapping.
	2.	Expose this engine via an MCP server with a small, stable tool surface:
	•	list_saf_mcp_techniques
	•	scan_technique
	•	explain_finding
	•	(Optional v2) propose_mitigation_patch
	3.	Clean separation of concerns:
	•	SAF‑MCP semantics encoded once in technique specs.
	•	Models treated as pluggable engines.
	•	MCP only handles transport and ergonomics.
	4.	Support usage from:
	•	MCP‑aware chat clients.
	•	IDE agents.
	•	CI pipelines (via CLI).

⸻

3. Non‑Goals
	•	Formal, sound static analysis (no proofs of absence of vulnerabilities).
	•	Full SAF‑MCP specification implementation; only the subset needed for code analysis.
	•	UI frontend beyond what MCP clients provide.
	•	Policy decision/approval workflows (out of scope for this phase).

⸻

4. High‑Level Architecture

4.1 Components
	•	Technique Spec Store
	•	Machine‑readable definitions of SAF‑MCP techniques, mitigations, and code signals (schema‑validated).
	•	SAF‑MCP Analysis Engine (Library + CLI)
	•	Loads technique specs plus SAF‑MCP corpus (READMEs, prioritized list, mitigations).
	•	Enumerates source/config/docs files with configurable globs/exts/size filters (docs allowed by default; 0 disables size checks).
	•	Runs a hybrid rules + LLM pipeline with per‑chunk prompts that include file path/extension/line range and README excerpt.
	•	Aggregates findings into a standardized AnalysisResult with mandatory evidence.
	•	Model Adapter Layer
	•	Generic CodeModel interface.
	•	Provider‑specific implementations (OpenAI, Anthropic, local) and retry wrapper; temperature pinned to 0.
	•	MCP Server (saf-mcp-analyzer)
	•	Implements MCP protocol.
	•	Exposes tools backed by the analysis engine.
	•	Translates MCP file handles/workspaces into local paths for the engine.

4.2 Logical Data Flow
	1.	MCP client calls scan_technique with technique_id and repo path/workspace root.
	2.	MCP server invokes the analysis engine with the given technique and repo (schema path provided by caller).
	3.	Engine:
	•	Loads technique spec (schema‑validated).
	•	Loads the technique README (fatal if missing) to supply detailed attack context to the model.
	•	Loads SAF‑MCP reference data (prioritized list, mitigation titles) and cross‑checks README vs filesystem.
	•	Enumerates and filters files (globs/exts/size); docs/manifests allowed unless explicitly excluded.
	•	Applies fast rules to identify candidate regions.
	•	Calls one or more LLMs via model adapters on code chunks (path/extension/lines + README excerpt in prompt).
	•	Optional LLM review can post‑filter findings; failures are non‑fatal and fall back to primary results.
	•	Aggregates results into an AnalysisResult with explicit evidence references for every status decision.
	4.	MCP server returns the AnalysisResult to the client as JSON.

⸻

5. Functional Requirements

5.1 Technique Management
	•	The system must support multiple SAF‑MCP techniques (e.g., T1101, T2003, …).
	•	Techniques must be defined as machine‑readable specs (YAML/JSON).
	•	MCP must expose a list of available techniques with metadata (ID, name, severity, short description).

5.2 Repo Scanning

Given:
	•	Technique ID
	•	Repo root path (on disk, mapped from MCP workspace)
	•	Optional configuration

The system must:
	•	Enumerate relevant source/config/docs files based on include/exclude globs/exts and optional max_file_bytes (0 disables size checks; docs/manifests allowed by default).
	•	Identify candidate code regions via lightweight heuristics/rules.
	•	Load the technique’s README (saf-mcp/techniques/<ID>/README.md) and feed its guidance into the model prompt for each scan (fatal if missing).
	•	Run LLM analysis on those regions using one or more CodeModel implementations (temperature pinned to 0; prompt includes file path/extension/line range).
	•	Optionally run a second‑pass LLM review to filter findings; review failures must not drop primary findings.
	•	Return, for that technique:
	•	Overall status (pass, fail, partial, unknown).
	•	Summary text.
	•	List of structured findings, each with:
	•	Severity
	•	File path
	•	Line range
	•	Evidence snippet (must cite the exact repo content used to justify the status)
	•	Observation text that references the cited evidence
	•	Associated mitigation IDs
	•	List of unknown_mitigations (potential new patterns not mapped to known mitigations).
	•	Metadata about models used and aggregation strategy.

5.3 Explain Finding

Given:
	•	Technique ID
	•	File path
	•	Line range

The system must:
	•	Load the relevant code chunk and neighboring context.
	•	Call a more detailed reasoning pass (potentially more expensive model / higher temperature).
	•	Return a more verbose explanation of:
	•	Why this is relevant to the technique.
	•	Impact.
	•	How it relates to mitigations.
	•	Implementation guidance at senior‑engineer level.

5.4 Propose Mitigation Patch (Optional / v2)

Given:
	•	Technique ID
	•	File path
	•	Line range

The system should be able to:
	•	Propose a candidate patch/diff (e.g., unified diff format) that mitigates the issue.
	•	Clearly mark this as advisory, not auto‑applied.

This is an optional stretch goal and can be implemented after the core pipeline.

⸻

6. Detailed Design

6.1 Technique Spec Store

6.1.1 Format
Use YAML or JSON files stored under a directory (e.g., techniques/).

Example YAML:

id: T1101
name: "Over-privileged MCP tool credentials"
severity: P1
summary: >
  Tool credentials are loaded and used with excessive privilege,
  lacking appropriate scoping, rotation, or isolation.
description: >
  ...
mitigations:
  - id: M1101.1
    description: "Scope tool token only to required operations."
  - id: M1101.2
    description: "Implement rotation policy and non-production tokens."
code_signals:
  - id: S1101.1
    description: "Env var names containing TOKEN or API_KEY used in HTTP client construction."
    heuristics:
      - pattern: "TOKEN"
      - pattern: "API_KEY"
languages:
  - "typescript"
  - "python"
  - "go"
  - "rust"
output_schema:
  requires_mitigations: true
  allowed_status_values:
    - pass
    - fail
    - partial
    - unknown

6.1.2 Requirements
	•	Engine must be able to:
	•	Load all technique specs on startup.
	•	Validate them against a schema (reject or warn on invalid).
	•	MCP list_saf_mcp_techniques must read from this store, not hard‑code techniques.
	•	Analysis must use the detailed technique reports (per-technique README.md) as part of the LLM prompt context when scanning, so findings reflect technique-specific guidance.

⸻

6.2 SAF‑MCP Analysis Engine

6.2.1 Public Interface (Library)
Language‑agnostic pseudo‑interface:

type AnalysisConfig = {
  include_globs?: string[];
  exclude_globs?: string[];
  max_file_bytes?: number;
  include_extensions?: string[];
  exclude_extensions?: string[];
  exclude_docs?: boolean; // default false (docs/manifests allowed)
  model_preference?: "local_only" | "remote_ok" | "specific";
  model_names?: string[]; // optional explicit list of models
  schema_path?: string; // explicit schema when running outside repo root
  scope?: ScanScope;
};

type ScanScope =
  | { type: "full_repo" }
  | { type: "file"; file: string }
  | { type: "selection"; file: string; start_line: number; end_line: number }
  | { type: "git_diff"; base_ref: string }; // changed-only vs base

function analyzeTechnique(
  techniqueId: string,
  repoPath: string,
  config: AnalysisConfig
): Promise<AnalysisResult>;

The engine MUST:
  • Load the technique’s detailed README.md content and include it in the LLM prompt to contextualize checks.
  • Return evidence for every finding: file path(s) and line ranges or snippets used to justify the status (pass/fail/partial/unknown).
  • Record which artifacts were consulted (files, technique README) so the result is auditable.

6.2.2 CLI
Binary name: saf-mcp-scan

Examples:

# Full repo for one technique
saf-mcp-scan T1101 /path/to/repo --json

# Changed-only scan vs origin/main
saf-mcp-scan T1101 /path/to/repo --json --scope git_diff --base origin/main

# Single-file scan
saf-mcp-scan T1101 /path/to/repo --file src/auth/mcp_proxy.rs --json

Minimal CLI flags:
	•	--json (output machine‑readable JSON AnalysisResult to stdout).
	•	--languages
	•	--include, --exclude
	•	--max-file-bytes
	•	--scope / --file / --selection
	•	--model-preference
	•	--model-names (optional).

6.2.3 Data Models
CodeChunk

type CodeChunk = {
  id: string;
  file: string;
  start_line: number;
  end_line: number;
  kind: "function" | "class" | "config_block" | "module" | "freeform";
  code: string;
  related_chunk_ids?: string[];
};

Finding

type Finding = {
  id: string;
  technique_id: string;
  severity: "P0" | "P1" | "P2" | "P3";
  file: string;
  start_line: number;
  end_line: number;
  evidence_snippet: string;
  observation: string; // plain-language explanation
  mitigation_ids: string[];
  mitigation_known_to_framework: boolean;
  source: "rule" | "llm" | "rule+llm";
  model_support?: {
    // optional: details about which models produced or agreed on this finding
    primary_model: string;
    supporting_models?: string[];
  };
};

UnknownMitigation

type UnknownMitigation = {
  id: string;
  technique_id: string;
  description: string;
  file: string;
  start_line: number;
  end_line: number;
  evidence_snippet: string;
};

AnalysisResult

type AnalysisStatus = "pass" | "fail" | "partial" | "unknown";

type AnalysisResult = {
  technique_id: string;
  status: AnalysisStatus;
  summary: string;
  findings: Finding[];
  unknown_mitigations: UnknownMitigation[];
  meta: {
    repo_path: string;
    scanned_at_utc: string;
    files_scanned: number;
    chunks_analyzed: number;
    config: AnalysisConfig;
    models: {
      name: string;
      role: "primary" | "secondary" | "local";
      findings_contributed: number;
    }[];
    aggregation_strategy: "union" | "intersection" | "primary_with_check";
  };
};

6.2.4 Internal Pipeline
	1.	Technique loading
	•	Load and validate technique spec for technique_id.
	2.	File enumeration
	•	Walk repoPath.
	•	Filter by language, globs, max_file_bytes.
	3.	Static heuristics / rules
	•	Optionally run AST/regex‑based rules to:
	•	Flag candidate files and line ranges.
	•	Extract signals relevant to the technique (e.g., env var usage, network calls, auth boundaries).
	•	Produce CodeChunk candidates with attached rule hit metadata.
	4.	LLM analysis
	•	For each candidate chunk:
	•	Build prompt using:
	•	Technique definition (summary, description, mitigations, code_signals).
	•	Chunk code.
	•	Any rule hits as “hints.”
	•	Required output schema.
	•	Call one or more CodeModel adapters.
	•	Collect model‑level findings into an intermediate ModelFinding representation.
	5.	Aggregation
	•	Merge overlapping / duplicate findings from multiple models.
	•	Apply aggregation strategy:
	•	union, intersection, or primary_with_check.
	•	Compute overall status:
	•	pass if no findings and enough context scanned.
	•	fail if at least one P0/P1 unmitigated.
	•	partial if both mitigated and unmitigated patterns present.
	•	unknown if scan is incomplete or inconclusive.
	6.	Result construction
	•	Build AnalysisResult object.
	•	Serialize as JSON for CLI and MCP.

⸻

6.3 Model Adapter Layer

6.3.1 Interface

type ModelFinding = {
  // low-level result from a single model before aggregation
  file: string;
  start_line: number;
  end_line: number;
  severity: "P0" | "P1" | "P2" | "P3";
  observation: string;
  mitigation_ids: string[];
  is_unknown_mitigation: boolean;
};

interface CodeModel {
  name: string;
  analyzeChunk(input: {
    techniqueId: string;
    techniqueDescription: string;
    mitigations: { id: string; description: string }[];
    codeChunk: CodeChunk;
    ruleHints?: string[]; // signals from static rules
  }): Promise<ModelFinding[]>;
}

6.3.2 Implementations
	•	OpenAIAdapter – calls OpenAI code/deep reasoning models.
	•	AnthropicAdapter – calls Claude code‑capable models.
	•	LocalModelAdapter – optional; e.g., vLLM or Llama.cpp.

Requirements:
	•	Respect global config: allow_remote_providers, allowed_providers.
	•	Enforce maximum prompt size and truncation strategy.
	•	Wrap API errors and timeouts with structured errors for the engine.

⸻

6.4 MCP Server: saf-mcp-analyzer

6.4.1 General
	•	Implements MCP spec for tools.
	•	Runs as a long‑lived process, configured via:
	•	Technique spec directory.
	•	Engine config (rules, model providers).
	•	Security policy (local‑only vs remote models).

The server should call the engine via library APIs where possible (not spawning separate CLI processes per call, except as a fallback).

6.4.2 Tool: list_saf_mcp_techniques
Purpose: Enumerate all known SAF‑MCP techniques.

Request:

{
  "type": "list_saf_mcp_techniques",
  "arguments": {}
}

Response:

{
  "techniques": [
    {
      "id": "T1101",
      "name": "Over-privileged MCP tool credentials",
      "severity": "P1",
      "summary": "Tool credentials are loaded and used with excessive privilege."
    }
    // ...
  ]
}

6.4.3 Tool: scan_technique
Purpose: Run a SAF‑MCP analysis for a technique over a repo.

Request:

{
  "type": "scan_technique",
  "arguments": {
    "technique_id": "T1101",
    "path": ".",          // root of MCP workspace
    "languages": ["ts", "js", "py"],
    "include_globs": ["src/**"],
    "exclude_globs": ["**/node_modules/**"],
    "max_file_bytes": 200000,
    "scope": {
      "type": "full_repo"
    },
    "model_preference": "remote_ok",
    "model_names": ["gpt-code-1"]
  }
}

Response:
	•	Must return the AnalysisResult schema defined in §6.2.3, serialized to JSON.

Example (truncated):

{
  "technique_id": "T1101",
  "status": "partial",
  "summary": "Found over-privileged MCP tool credentials in auth layer.",
  "findings": [
    {
      "id": "F-1",
      "technique_id": "T1101",
      "severity": "P1",
      "file": "src/auth/mcp_proxy.rs",
      "start_line": 120,
      "end_line": 168,
      "evidence_snippet": "let token = env::var(\"MCP_TOOL_TOKEN\")?...",
      "observation": "Tool token is loaded from env and reused for multiple tools with no scoping or rotation.",
      "mitigation_ids": ["M1101.2"],
      "mitigation_known_to_framework": true,
      "source": "rule+llm",
      "model_support": {
        "primary_model": "gpt-code-1",
        "supporting_models": ["claude-code-x"]
      }
    }
  ],
  "unknown_mitigations": [],
  "meta": {
    "repo_path": ".",
    "scanned_at_utc": "2025-11-20T12:34:56Z",
    "files_scanned": 42,
    "chunks_analyzed": 130,
    "config": { /* ... */ },
    "models": [
      { "name": "gpt-code-1", "role": "primary", "findings_contributed": 3 }
    ],
    "aggregation_strategy": "primary_with_check"
  }
}

6.4.4 Tool: explain_finding
Purpose: Provide a deeper explanation for an existing finding.

Request:

{
  "type": "explain_finding",
  "arguments": {
    "technique_id": "T1101",
    "file": "src/auth/mcp_proxy.rs",
    "start_line": 120,
    "end_line": 168
  }
}

Behavior:
	•	Server:
	•	Resolves file against MCP workspace.
	•	Extracts the relevant lines and some surrounding context (configurable window).
	•	Calls a dedicated explainFinding function in the engine, which:
	•	Re‑prompts a model with the technique spec and code.
	•	Asks for a detailed explanation and remediation guidance.

Response:

{
  "technique_id": "T1101",
  "file": "src/auth/mcp_proxy.rs",
  "start_line": 120,
  "end_line": 168,
  "explanation": "In this block, the MCP tool token is loaded from the process environment and reused for multiple tools...",
  "impact": "If the token is compromised, an attacker gains broad access to multiple MCP tools...",
  "recommended_mitigations": [
    {
      "mitigation_id": "M1101.2",
      "description": "Implement token rotation and scope tokens per tool or per capability."
    }
  ],
  "model": "gpt-code-1"
}

6.4.5 Tool: propose_mitigation_patch (Optional / v2)
Request:

{
  "type": "propose_mitigation_patch",
  "arguments": {
    "technique_id": "T1101",
    "file": "src/auth/mcp_proxy.rs",
    "start_line": 120,
    "end_line": 168
  }
}

Response:

{
  "technique_id": "T1101",
  "file": "src/auth/mcp_proxy.rs",
  "patch_format": "unified_diff",
  "patch": "--- a/src/auth/mcp_proxy.rs\n+++ b/src/auth/mcp_proxy.rs\n@@ -120,7 +120,18 @@\n- let token = env::var(\"MCP_TOOL_TOKEN\")?...",
  "notes": "Review and adapt this patch before applying. This is a suggested mitigation."
}


⸻

7. Configuration & Deployment

7.1 Configuration Sources
	•	Config file (e.g., config.yaml).
	•	Environment variables for secrets and provider keys.
	•	Command‑line overrides for CLI usage.

Example config fields:

techniques_dir: "./techniques"
allow_remote_providers: true
allowed_providers:
  - openai
  - anthropic
default_models:
  primary: "gpt-code-1"
  secondary: "claude-code-x"
max_file_bytes: 200000
exclude_globs:
  - "**/node_modules/**"
  - "**/dist/**"
redaction_rules:
  - pattern: "(?i)secret"
  - pattern: "(?i)password"

7.2 Secrets
	•	Provider API keys must be loaded from environment variables or a secret manager.
	•	Keys must never be logged.
	•	Config must support running in:
	•	Local‑only mode (only LocalModelAdapter).
	•	Remote‑allowed mode with provider restrictions.

7.3 Packaging
	•	Target as a containerized service (Docker image) for:
	•	MCP server.
	•	CLI usage inside CI (same image or stripped‑down variant).

⸻

8. Security & Privacy Requirements
	•	Provide a configuration flag to:
	•	Disallow remote providers entirely.
	•	Restrict which providers are used.
	•	Provide explicit allow/deny lists for:
	•	File paths never to send to remote providers (e.g., **/.env, **/secrets/**).
	•	Logs:
	•	Must not include full code unless explicitly enabled with a secure flag.
	•	Must redact secrets based on redaction_rules.
	•	Network calls:
	•	Must use TLS for all remote providers.
	•	Timeouts and retry behavior must be well‑defined.

⸻

9. Telemetry & Observability
	•	Structured logs with:
	•	Technique ID.
	•	Repo path (hashed or anonymized for privacy, if needed).
	•	Scan duration.
	•	Number of files and chunks.
	•	Models used and call counts.
	•	Metrics:
	•	Scans per minute.
	•	Average scan duration per technique.
	•	LLM call latency and error rates.
	•	Finding counts by severity and technique (optional, with privacy considerations).
	•	Optional: debug mode to log full prompts and responses for development, gated by a secure config flag.

⸻

10. Performance Requirements
	•	Must handle repositories up to at least:
	•	1,000 files and 200 KLOC with acceptable latency (e.g., single‑digit minutes for full scans; shorter for diff‑based scans).
	•	Must support concurrent scans:
	•	Configurable worker pool size for chunk analysis.
	•	Rate limiting for provider APIs.

⸻

11. Testing & Validation

11.1 Unit Tests
	•	Technique spec parsing and validation.
	•	File enumeration and filtering logic.
	•	Chunking logic (per language, where applicable).
	•	Rules engine (if rules are implemented).
	•	Aggregation logic for multi‑model findings.

11.2 Integration Tests
	•	End‑to‑end scans on small synthetic repos:
	•	Known vulnerable patterns and mitigated patterns.
	•	Expected AnalysisResult compared with golden JSON.
	•	MCP tools integration:
	•	list_saf_mcp_techniques returns correct technique metadata.
	•	scan_technique returns valid JSON and maps paths correctly from MCP workspace.
	•	explain_finding returns plausible explanations (manually reviewed during development).

11.3 Provider‑Specific Tests
	•	Adapters for each provider must be tested with:
	•	Successful responses.
	•	Timeouts.
	•	API quota errors.
	•	Network failures.

⸻

12. Delivery Phases

Phase 0 – Foundations
	•	Implement technique spec schema + loader.
	•	Implement minimal AnalysisResult and CLI that:
	•	Enumerates files.
	•	Uses a single model (e.g., OpenAI) to scan a tiny repo.

Phase 1 – Core Engine
	•	Implement:
	•	Chunking.
	•	Basic rules (where useful).
	•	CodeModel interface + at least one adapter.
	•	Aggregation into AnalysisResult.
	•	Provide saf-mcp-scan CLI for full repo and single‑file scopes.

Phase 2 – MCP Server
	•	Implement saf-mcp-analyzer MCP server with:
	•	list_saf_mcp_techniques
	•	scan_technique
	•	explain_finding
	•	Integrate with MCP clients for manual testing.

Phase 3 – Hardening & UX
	•	Add:
	•	Multi‑model support.
	•	Incremental / diff‑based scanning.
	•	Security configuration (local‑only mode, provider restrictions, redaction).
	•	Improve explanations and summaries based on feedback.

Phase 4 – Optional Enhancements
	•	Implement propose_mitigation_patch.
	•	SARIF output option for the CLI.
	•	Deeper analytics on findings over time.

⸻

This spec is intended as the blueprint for implementation. The team should treat the schemas and tool signatures as stable interfaces, and iterate mainly on internal heuristics, prompts, and model configurations.
