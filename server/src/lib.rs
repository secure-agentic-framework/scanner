use std::fs;
use std::path::{Path, PathBuf};
use std::env;
use std::sync::Arc;
use std::time::Duration;

use rmcp::{
    handler::server::{
        tool::ToolRouter,
        wrapper::{Json, Parameters},
    },
    model::{CallToolResult, Content, JsonObject, Tool, ToolAnnotations},
    schemars::JsonSchema,
    serde_json, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};
use serde::{Deserialize, Serialize};

/// Generic tool argument descriptor for MCP tool registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolArgument {
    pub name: String,
    pub required: bool,
    pub description: String,
    pub r#type: String,
}

/// Generic tool definition for MCP tool registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub arguments: Vec<ToolArgument>,
    pub response: String,
}

/// Return MCP Tool descriptors for all supported tools.
pub fn mcp_tools() -> Vec<Tool> {
    vec![
        list_saf_mcp_techniques_tool(),
        scan_technique_tool(),
        explain_finding_tool(),
        propose_mitigation_patch_tool(),
    ]
    .into_iter()
    .map(definition_to_tool)
    .collect()
}

fn definition_to_tool(def: ToolDefinition) -> Tool {
    let ToolDefinition {
        name,
        description,
        arguments,
        response,
    } = def;

    let mut properties = JsonObject::new();
    let mut required = Vec::new();
    for arg in arguments {
        let mut schema = JsonObject::new();
        schema.insert("type".into(), serde_json::Value::String(arg.r#type));
        schema.insert(
            "description".into(),
            serde_json::Value::String(arg.description),
        );
        properties.insert(arg.name.clone(), serde_json::Value::Object(schema));
        if arg.required {
            required.push(serde_json::Value::String(arg.name));
        }
    }
    let mut input_schema = JsonObject::new();
    input_schema.insert("type".into(), serde_json::Value::String("object".into()));
    input_schema.insert("properties".into(), serde_json::Value::Object(properties));
    if !required.is_empty() {
        input_schema.insert("required".into(), serde_json::Value::Array(required));
    }
    // Allow additional properties so servers can accept backward-compatible or server-supplied fields.
    input_schema.insert("additionalProperties".into(), serde_json::Value::Bool(true));

    let mut output_schema = JsonObject::new();
    output_schema.insert("description".into(), serde_json::Value::String(response));

    Tool {
        name: name.into(),
        title: None,
        description: Some(description.into()),
        input_schema: Arc::new(input_schema),
        output_schema: Some(Arc::new(output_schema)),
        annotations: Some(ToolAnnotations::new().read_only(true)),
        icons: None,
    }
}

#[derive(Clone)]
pub struct SafMcpServer {
    tool_router: ToolRouter<Self>,
}

impl Default for SafMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl SafMcpServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router]
impl SafMcpServer {
    /// List techniques from validated specs.
    #[tool(
        name = "list_saf_mcp_techniques",
        description = "List SAF-MCP techniques with metadata."
    )]
    async fn tool_list(
        &self,
        params: Parameters<ListParams>,
    ) -> Result<Json<Vec<TechniqueListItem>>, McpError> {
        let prioritized = params
            .0
            .prioritized_path
            .as_ref()
            .map(std::path::PathBuf::from);
        let items = list_saf_mcp_techniques(
            &resolve_spec_dir(params.0.spec_dir.as_deref()),
            &resolve_schema_path(params.0.schema_path.as_deref()),
            prioritized.as_deref(),
        )
        .map_err(as_mcp_internal)?;
        Ok(Json(items))
    }

    /// Scan a technique against a repo path.
    #[tool(
        name = "scan_technique",
        description = "Scan a repository for a given SAF-MCP technique and return structured findings."
    )]
    async fn tool_scan(
        &self,
        params: Parameters<ScanParams>,
    ) -> Result<Json<SerializableAnalyzeOutput>, McpError> {
        let scope = parse_scope(&params.0)?;
        let cfg = engine::config::load_config(
            params
                .0
                .config
                .as_deref()
                .map(std::path::PathBuf::from)
                .as_deref(),
        )
        .map_err(|e| McpError::internal_error(format!("config error: {e}"), None))?;
        let filters = parse_filters(&params.0, &cfg);
        let provider = parse_provider(params.0.provider.as_deref())?;
        let args = ScanArgs {
            technique_id: params.0.technique_id.clone(),
            repo_path: resolve_repo_path(&params.0)?,
            spec_dir: resolve_spec_dir(params.0.spec_dir.as_deref()),
            schema_path: resolve_schema_path(params.0.schema_path.as_deref()),
            saf_mcp_root: resolve_saf_mcp_root(params.0.saf_mcp_root.as_deref()),
            scope,
            max_lines_per_chunk: params.0.max_lines_per_chunk.unwrap_or(200),
            filters,
            provider,
            model_name: params.0.model_name.clone(),
            config: params.0.config.as_ref().map(std::path::PathBuf::from),
        };
        let output = handle_scan_technique(args).await.map_err(as_mcp_internal)?;
        Ok(Json(to_serializable_output(output)))
    }

    /// Explain finding placeholder.
    #[tool(
        name = "explain_finding",
        description = "Explain a finding (placeholder)."
    )]
    async fn tool_explain(
        &self,
        params: Parameters<ExplainParams>,
    ) -> Result<CallToolResult, McpError> {
        let snippet = read_snippet(&params.0.file, params.0.start_line, params.0.end_line)?;
        let body = format!(
            "Technique {technique}\nFile: {file}:{start}-{end}\nSnippet:\n{snippet}",
            technique = params.0.technique_id,
            file = params.0.file,
            start = params.0.start_line,
            end = params.0.end_line,
            snippet = snippet
        );
        Ok(CallToolResult::success(vec![Content::text(body)]))
    }

    /// Propose mitigation placeholder.
    #[tool(
        name = "propose_mitigation_patch",
        description = "Propose a mitigation patch (placeholder)."
    )]
    async fn tool_propose(
        &self,
        _params: Parameters<ProposeParams>,
    ) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(
            "propose_mitigation_patch not implemented yet",
        )]))
    }
}

#[tool_handler]
impl ServerHandler for SafMcpServer {}

#[derive(Debug, Clone, serde::Serialize, JsonSchema)]
pub struct TechniqueListItem {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub summary: String,
}

/// Arguments for list_saf_mcp_techniques handler.
#[derive(Debug, Clone)]
pub struct ListArgs {
    pub spec_dir: std::path::PathBuf,
    pub schema_path: std::path::PathBuf,
    pub prioritized_path: Option<std::path::PathBuf>,
}

/// Arguments for scan_technique handler.
#[derive(Debug, Clone)]
pub struct ScanArgs {
    pub technique_id: String,
    pub repo_path: std::path::PathBuf,
    pub spec_dir: std::path::PathBuf,
    pub schema_path: std::path::PathBuf,
    pub saf_mcp_root: std::path::PathBuf,
    pub scope: engine::chunk::ScopeKind,
    pub max_lines_per_chunk: usize,
    pub filters: Option<engine::chunk::PathFilters>,
    pub provider: Provider,
    pub model_name: Option<String>,
    pub config: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone)]
pub enum Provider {
    Local,
    OpenAI,
    Anthropic,
}

/// Resolve a path against a workspace root, preventing traversal.
pub fn resolve_workspace_path(
    workspace_root: &std::path::Path,
    input: &str,
) -> Result<std::path::PathBuf, String> {
    let root = workspace_root
        .canonicalize()
        .map_err(|e| format!("failed to resolve workspace root: {e}"))?;

    // Build the path manually to avoid traversal; do not require the final path to exist.
    let mut acc = root.clone();
    for c in std::path::Path::new(input).components() {
        match c {
            std::path::Component::ParentDir => {
                return Err(format!(
                    "path {} escapes workspace {}",
                    input,
                    root.display()
                ))
            }
            std::path::Component::RootDir => continue,
            std::path::Component::CurDir => continue,
            std::path::Component::Normal(p) => acc.push(p),
            _ => {}
        }
    }

    // Canonicalize the deepest existing ancestor to resolve symlinks.
    let mut ancestor = acc.as_path();
    while !ancestor.exists() {
        if let Some(p) = ancestor.parent() {
            ancestor = p;
        } else {
            break;
        }
    }
    let ancestor_canon = ancestor
        .canonicalize()
        .map_err(|e| format!("failed to canonicalize path {}: {e}", ancestor.display()))?;
    let suffix = acc
        .strip_prefix(ancestor)
        .unwrap_or(std::path::Path::new(""));
    let final_path = ancestor_canon.join(suffix);

    let final_canon = if final_path.exists() {
        final_path
            .canonicalize()
            .map_err(|e| format!("failed to canonicalize path {}: {e}", final_path.display()))?
    } else {
        final_path.clone()
    };

    if !final_canon.starts_with(&root) {
        return Err(format!(
            "path {} escapes workspace {}",
            final_canon.display(),
            root.display()
        ));
    }
    Ok(final_path)
}

pub fn list_saf_mcp_techniques_tool() -> ToolDefinition {
    ToolDefinition {
        name: "list_saf_mcp_techniques".into(),
        description: "List SAF-MCP techniques with id, name, severity, and summary.".into(),
        arguments: vec![],
        response: "array of { id, name, severity, summary }".into(),
    }
}

/// List techniques from validated specs, optionally ordered by prioritized list.
pub fn list_saf_mcp_techniques(
    spec_dir: &std::path::Path,
    schema_path: &std::path::Path,
    prioritized_path: Option<&std::path::Path>,
) -> Result<Vec<TechniqueListItem>, String> {
    let validation = engine::validate_techniques(spec_dir, schema_path)
        .map_err(|e| format!("schema error: {e}"))?;
    if !validation.errors.is_empty() {
        let msgs = validation
            .errors
            .iter()
            .map(|e| format!("{}: {}", e.path.display(), e.messages.join("; ")))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("technique validation failed: {msgs}"));
    }
    let cache = engine::TechniqueCache::new(validation.techniques);
    let mut items: Vec<TechniqueListItem> = cache
        .metadata()
        .iter()
        .map(|m| TechniqueListItem {
            id: m.id.clone(),
            name: m.name.clone(),
            severity: m.severity.clone(),
            summary: m.summary.clone(),
        })
        .collect();

    if let Some(path) = prioritized_path {
        let prioritized = engine::prioritized::parse_prioritized_techniques(path);
        if !prioritized.errors.is_empty() {
            let msg = prioritized
                .errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(format!("failed to parse prioritized techniques: {msg}"));
        }
        let mut order: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (idx, t) in prioritized.techniques.iter().enumerate() {
            order.insert(normalize_id(&t.id), idx);
        }
        items.sort_by(|a, b| {
            let oa = order.get(&normalize_id(&a.id));
            let ob = order.get(&normalize_id(&b.id));
            match (oa, ob) {
                (Some(ia), Some(ib)) => ia.cmp(ib),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                _ => a.id.cmp(&b.id),
            }
        });
    } else {
        items.sort_by(|a, b| a.id.cmp(&b.id));
    }

    Ok(items)
}

/// Handler-friendly wrapper that returns technique list items.
pub fn handle_list_saf_mcp_techniques(args: ListArgs) -> Result<Vec<TechniqueListItem>, String> {
    list_saf_mcp_techniques(
        &args.spec_dir,
        &args.schema_path,
        args.prioritized_path.as_deref(),
    )
}

/// Handler-friendly scan execution; caller supplies model adapter.
pub async fn handle_scan_technique(
    args: ScanArgs,
) -> Result<engine::entrypoint::AnalyzeOutput, String> {
    let cfg = engine::config::load_config(args.config.as_deref())
        .map_err(|e| format!("config error: {e}"))?;
    let model = build_model(&args, &cfg)?;
    let saf_mcp_techniques = args.saf_mcp_root.join("techniques");
    let mitigations_dir = args.saf_mcp_root.join("mitigations");
    let prioritized_path = saf_mcp_techniques.join("prioritized-techniques.md");
    let readme_path = args.saf_mcp_root.join("README.md");

    engine::entrypoint::analyze_technique(
        &model,
        &args.technique_id,
        &args.repo_path,
        &args.spec_dir,
        &args.schema_path,
        &mitigations_dir,
        &saf_mcp_techniques,
        &prioritized_path,
        &readme_path,
        args.scope,
        args.max_lines_per_chunk,
        args.filters.clone(),
    )
    .await
}

fn build_model(args: &ScanArgs, cfg: &engine::config::Config) -> Result<ModelBox, String> {
    let retries = cfg.retry_max_retries.unwrap_or(0);
    let delay = Duration::from_millis(cfg.retry_delay_ms.unwrap_or(500));
    let timeout = cfg.timeout_ms.map(Duration::from_millis);

    let base = match args.provider {
        Provider::Local => {
            engine::config::enforce_provider_allowlist(cfg, "local")?;
            ModelBox(Arc::new(engine::adapters::local::LocalModel::default()))
        }
        Provider::OpenAI => {
            engine::config::enforce_provider_allowlist(cfg, "openai")?;
            let key = cfg
                .openai_api_key
                .clone()
                .ok_or_else(|| "OPENAI_API_KEY not set".to_string())?;
            let name = args
                .model_name
                .clone()
                .or_else(|| cfg.model_names.clone().and_then(|m| m.get(0).cloned()))
                .unwrap_or_else(|| "gpt-4o-mini".to_string());
            ModelBox(Arc::new(engine::adapters::openai::OpenAIModel::new(
                name, key, cfg.openai_base_url.clone()
            )))
        }
        Provider::Anthropic => {
            engine::config::enforce_provider_allowlist(cfg, "anthropic")?;
            let key = cfg
                .anthropic_api_key
                .clone()
                .ok_or_else(|| "ANTHROPIC_API_KEY not set".to_string())?;
            let name = args
                .model_name
                .clone()
                .or_else(|| cfg.model_names.clone().and_then(|m| m.get(0).cloned()))
                .unwrap_or_else(|| "claude-3-5-sonnet-20240620".to_string());
            ModelBox(Arc::new(engine::adapters::anthropic::AnthropicModel::new(
                name, key,
            )))
        }
    };

    Ok(if retries > 0 || timeout.is_some() {
        ModelBox(Arc::new(engine::adapters::retry::RetryModel::new(
            base, retries, delay, timeout,
        )))
    } else {
        base
    })
}

#[derive(Clone)]
struct ModelBox(Arc<dyn engine::codemodel::CodeModel + Send + Sync>);

#[async_trait::async_trait]
impl engine::codemodel::CodeModel for ModelBox {
    fn name(&self) -> &str {
        self.0.name()
    }

    async fn analyze_chunk(
        &self,
        prompt: &engine::prompt::PromptPayload,
    ) -> Result<Vec<engine::codemodel::ModelFinding>, engine::codemodel::CodeModelError> {
        self.0.analyze_chunk(prompt).await
    }
}
fn normalize_id(id: &str) -> String {
    if let Some(stripped) = id.strip_prefix("SAF-") {
        stripped.to_string()
    } else {
        id.to_string()
    }
}

pub fn scan_technique_tool() -> ToolDefinition {
    ToolDefinition {
        name: "scan_technique".into(),
        description: "Scan a repository for a given SAF-MCP technique.".into(),
        arguments: vec![
            arg("technique_id", true, "Technique id (SAF-T####).", "string"),
            arg("path", true, "Repository path to scan.", "string"),
            arg(
                "scope",
                false,
                "Scan scope: full|file|selection|git_diff.",
                "string",
            ),
            arg(
                "file",
                false,
                "Path to file (required for scope=file or selection).",
                "string",
            ),
            arg(
                "selection",
                false,
                "Line range (start-end) when scope=selection.",
                "string",
            ),
            arg(
                "base_ref",
                false,
                "Base ref for git_diff scope (defaults to origin/main).",
                "string",
            ),
            arg(
                "provider",
                false,
                "Model provider: local|openai|anthropic (defaults to local).",
                "string",
            ),
            arg(
                "model_name",
                false,
                "Optional model name override.",
                "string",
            ),
            arg(
                "max_lines_per_chunk",
                false,
                "Maximum lines per code chunk (default 200).",
                "number",
            ),
            arg(
                "include_extensions",
                false,
                "Comma-separated file extensions to include (without dot).",
                "string",
            ),
            arg(
                "exclude_extensions",
                false,
                "Comma-separated file extensions to exclude (without dot).",
                "string",
            ),
            arg(
                "include_globs",
                false,
                "Comma-separated glob patterns to include.",
                "string",
            ),
            arg(
                "exclude_globs",
                false,
                "Comma-separated glob patterns to exclude.",
                "string",
            ),
            arg(
                "max_file_bytes",
                false,
                "Skip files larger than this many bytes.",
                "number",
            ),
            arg(
                "config",
                false,
                "Optional config file path for provider settings.",
                "string",
            ),
        ],
        response: "AnalysisResult JSON (status, findings with evidence, metadata).".into(),
    }
}

pub fn explain_finding_tool() -> ToolDefinition {
    ToolDefinition {
        name: "explain_finding".into(),
        description: "Explain a finding for a given file/line range and technique.".into(),
        arguments: vec![
            arg("technique_id", true, "Technique id (SAF-T####).", "string"),
            arg("file", true, "Path to file.", "string"),
            arg("start_line", true, "Start line of the finding.", "number"),
            arg("end_line", true, "End line of the finding.", "number"),
        ],
        response: "Explanation payload with impact and recommended mitigations.".into(),
    }
}

pub fn propose_mitigation_patch_tool() -> ToolDefinition {
    ToolDefinition {
        name: "propose_mitigation_patch".into(),
        description: "Optional placeholder: propose a mitigation patch for a finding.".into(),
        arguments: vec![
            arg("technique_id", true, "Technique id (SAF-T####).", "string"),
            arg("file", true, "File to patch.", "string"),
            arg(
                "patch_format",
                true,
                "Patch format (unified, git).",
                "string",
            ),
            arg(
                "context",
                false,
                "Optional extra context for patch generation.",
                "string",
            ),
        ],
        response: "Stub response indicating not implemented.".into(),
    }
}

fn arg(name: &str, required: bool, description: &str, r#type: &str) -> ToolArgument {
    ToolArgument {
        name: name.into(),
        required,
        description: description.into(),
        r#type: r#type.into(),
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ListParams {
    pub spec_dir: Option<String>,
    pub schema_path: Option<String>,
    pub prioritized_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ScanParams {
    pub technique_id: String,
    pub path: Option<String>,
    pub repo_path: Option<String>,
    pub spec_dir: Option<String>,
    pub schema_path: Option<String>,
    pub saf_mcp_root: Option<String>,
    pub scope: Option<String>,
    pub file: Option<String>,
    pub selection: Option<String>,
    pub base_ref: Option<String>,
    pub max_lines_per_chunk: Option<usize>,
    pub include_extensions: Option<String>,
    pub exclude_extensions: Option<String>,
    pub include_globs: Option<String>,
    pub exclude_globs: Option<String>,
    pub max_file_bytes: Option<u64>,
    pub provider: Option<String>,
    pub model_name: Option<String>,
    pub config: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ExplainParams {
    pub technique_id: String,
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ProposeParams {
    pub technique_id: String,
    pub file: String,
    pub patch_format: String,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SerializableAnalyzeOutput {
    pub status: String,
    pub summary: String,
    pub model_support: Vec<String>,
    pub findings: Vec<SerializableFinding>,
    pub missing_techniques: Vec<String>,
    pub extra_techniques: Vec<String>,
    pub mitigation_titles: Vec<(String, String)>,
    pub readme_path: String,
    pub scanned_at_utc: String,
    pub files_scanned: usize,
    pub chunks_analyzed: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SerializableFinding {
    pub chunk_id: String,
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub severity: String,
    pub observation: String,
    pub evidence: String,
    pub model_support: Vec<String>,
    pub unknown_mitigations: Vec<String>,
}

fn as_mcp_internal(err: String) -> McpError {
    McpError::internal_error(err, None)
}

fn parse_provider(name: Option<&str>) -> Result<Provider, McpError> {
    match name.unwrap_or("local").to_lowercase().as_str() {
        "local" => Ok(Provider::Local),
        "openai" => Ok(Provider::OpenAI),
        "anthropic" => Ok(Provider::Anthropic),
        other => Err(McpError::invalid_params(
            format!("unknown provider: {other}"),
            None,
        )),
    }
}

fn parse_scope(params: &ScanParams) -> Result<engine::chunk::ScopeKind, McpError> {
    match params.scope.as_deref().unwrap_or("full_repo") {
        "full_repo" | "full" => Ok(engine::chunk::ScopeKind::FullRepo),
        "file" => {
            let file = params
                .file
                .as_ref()
                .ok_or_else(|| McpError::invalid_params("file scope requires file", None))?;
            Ok(engine::chunk::ScopeKind::File {
                file: std::path::PathBuf::from(file),
            })
        }
        "selection" => {
            let file = params
                .file
                .as_ref()
                .ok_or_else(|| McpError::invalid_params("selection scope requires file", None))?;
            let sel = params.selection.as_ref().ok_or_else(|| {
                McpError::invalid_params("selection scope requires selection", None)
            })?;
            let (start, end) = parse_range(sel)?;
            Ok(engine::chunk::ScopeKind::Selection {
                file: std::path::PathBuf::from(file),
                start_line: start,
                end_line: end,
            })
        }
        "git_diff" => {
            let base = params
                .base_ref
                .clone()
                .unwrap_or_else(|| "origin/main".into());
            Ok(engine::chunk::ScopeKind::GitDiff { base_ref: base })
        }
        other => Err(McpError::invalid_params(
            format!("unknown scope: {other}"),
            None,
        )),
    }
}

fn parse_range(input: &str) -> Result<(usize, usize), McpError> {
    let mut parts = input.split('-');
    let start = parts
        .next()
        .ok_or_else(|| McpError::invalid_params("missing start", None))?
        .parse::<usize>()
        .map_err(|_| McpError::invalid_params("invalid start", None))?;
    let end = parts
        .next()
        .ok_or_else(|| McpError::invalid_params("missing end", None))?
        .parse::<usize>()
        .map_err(|_| McpError::invalid_params("invalid end", None))?;
    if start == 0 || end == 0 || end < start {
        return Err(McpError::invalid_params(
            "selection must be start-end with start<=end and >=1",
            None,
        ));
    }
    Ok((start, end))
}

fn read_snippet(path: &str, start: usize, end: usize) -> Result<String, McpError> {
    if start == 0 || end < start {
        return Err(McpError::invalid_params(
            "invalid line range: start must be >=1 and start<=end",
            None,
        ));
    }
    let root = env::var("WORKSPACE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let root_canon = root
        .canonicalize()
        .map_err(|e| McpError::internal_error(format!("failed to resolve workspace root: {e}"), None))?;
    let resolved = if Path::new(path).is_absolute() {
        let abs = Path::new(path).canonicalize().map_err(|e| {
            McpError::invalid_params(format!("invalid file path {path}: {e}"), None)
        })?;
        if !abs.starts_with(&root_canon) {
            return Err(McpError::invalid_params(
                "path escapes workspace root",
                None,
            ));
        }
        abs
    } else {
        resolve_workspace_path(&root, path).map_err(|e| McpError::invalid_params(e, None))?
    };
    let content = fs::read_to_string(&resolved).map_err(|e| {
        McpError::internal_error(format!("failed to read file {path}: {e}"), None)
    })?;
    let lines: Vec<&str> = content.lines().collect();
    if start > lines.len() || end > lines.len() {
        return Err(McpError::invalid_params(
            "line range outside file bounds",
            None,
        ));
    }
    let snippet = lines[start - 1..end].join("\n");
    Ok(snippet)
}

fn parse_filters(
    params: &ScanParams,
    cfg: &engine::config::Config,
) -> Option<engine::chunk::PathFilters> {
    let cfg_max = match cfg.max_file_bytes {
        Some(0) => None,
        other => other,
    };
    let mut filters = engine::chunk::PathFilters {
        include_extensions: cfg.include_extensions.clone().unwrap_or_default(),
        exclude_extensions: cfg.exclude_extensions.clone().unwrap_or_default(),
        include_globs: cfg.include_globs.clone().unwrap_or_default(),
        exclude_globs: cfg.exclude_globs.clone().unwrap_or_default(),
        max_file_bytes: cfg_max,
        exclude_docs: false,
    };
    if let Some(exts) = &params.include_extensions {
        filters.include_extensions = split_csv(exts);
    }
    if let Some(exts) = &params.exclude_extensions {
        filters.exclude_extensions = split_csv(exts);
    }
    if let Some(globs) = &params.include_globs {
        filters.include_globs = split_csv(globs);
    }
    if let Some(globs) = &params.exclude_globs {
        filters.exclude_globs = split_csv(globs);
    }
    if let Some(bytes) = params.max_file_bytes {
        filters.max_file_bytes = if bytes == 0 { None } else { Some(bytes) };
    }
    Some(filters)
}

fn split_csv(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn to_serializable_output(output: engine::entrypoint::AnalyzeOutput) -> SerializableAnalyzeOutput {
    let status = match output.analysis.status {
        engine::status::AnalysisStatus::Pass => "pass",
        engine::status::AnalysisStatus::Fail => "fail",
        engine::status::AnalysisStatus::Partial => "partial",
        engine::status::AnalysisStatus::Unknown => "unknown",
    }
    .to_string();
    let findings = output
        .analysis
        .findings
        .into_iter()
        .map(|f| SerializableFinding {
            chunk_id: f.chunk_id,
            file: f.file,
            start_line: f.start_line,
            end_line: f.end_line,
            severity: f.severity,
            observation: f.observation,
            evidence: f.evidence,
            model_support: f.model_support,
            unknown_mitigations: f.unknown_mitigations,
        })
        .collect();
    SerializableAnalyzeOutput {
        status,
        summary: output.analysis.summary,
        model_support: output.analysis.model_support,
        findings,
        missing_techniques: output.missing_techniques,
        extra_techniques: output.extra_techniques,
        mitigation_titles: output.mitigation_titles,
        readme_path: output.readme_path,
        scanned_at_utc: output.analysis.meta.scanned_at_utc,
        files_scanned: output.analysis.meta.files_scanned,
        chunks_analyzed: output.analysis.meta.chunks_analyzed,
    }
}

fn resolve_spec_dir(override_path: Option<&str>) -> std::path::PathBuf {
    override_path
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var("SPEC_DIR").ok().map(std::path::PathBuf::from))
        .unwrap_or_else(|| project_root().join("techniques"))
}

fn resolve_schema_path(override_path: Option<&str>) -> std::path::PathBuf {
    override_path
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var("SCHEMA_PATH")
                .ok()
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(|| project_root().join("schemas").join("technique.schema.json"))
}

fn resolve_saf_mcp_root(override_path: Option<&str>) -> std::path::PathBuf {
    override_path
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var("SAF_MCP_ROOT")
                .ok()
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(|| project_root().join("saf-mcp"))
}

fn resolve_repo_path(params: &ScanParams) -> Result<std::path::PathBuf, McpError> {
    params
        .repo_path
        .as_ref()
        .or(params.path.as_ref())
        .map(std::path::PathBuf::from)
        .ok_or_else(|| McpError::invalid_params("missing path", None))
}

fn project_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_spec(dir: &std::path::Path, name: &str, body: &str) {
        let path = dir.join(name);
        let mut f = File::create(path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    }

    #[test]
    fn lists_techniques_with_prioritized_order() {
        let dir = tempdir().unwrap();
        let spec_dir = dir.path().join("specs");
        std::fs::create_dir_all(&spec_dir).unwrap();

        let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("schemas")
            .join("technique.schema.json");

        let t1 = r#"
id: "T1001"
name: "First"
severity: "P1"
summary: "S1"
description: "D"
mitigations:
  - id: "M1"
    description: "Mit"
code_signals:
  - id: "S1"
    description: "Sig"
    heuristics:
      - pattern: "foo"
languages: ["rust"]
output_schema:
  requires_mitigations: false
  allowed_status_values: ["pass","fail"]
"#;
        let t2 = t1.replace("T1001", "T1002").replace("First", "Second");
        write_spec(&spec_dir, "t1.yaml", t1);
        write_spec(&spec_dir, "t2.yaml", t2.as_str());

        let prioritized_path = dir.path().join("prioritized-techniques.md");
        let mut pf = File::create(&prioritized_path).unwrap();
        writeln!(
            pf,
            "| Technique ID | Name |\n| SAF-T1002 | Second |\n| SAF-T1001 | First |\n"
        )
        .unwrap();

        let items =
            list_saf_mcp_techniques(&spec_dir, &schema_path, Some(&prioritized_path)).unwrap();
        let ids: Vec<_> = items.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, vec!["T1002", "T1001"]);
    }

    #[test]
    fn errors_on_validation_failure() {
        let dir = tempdir().unwrap();
        let spec_dir = dir.path().join("specs");
        std::fs::create_dir_all(&spec_dir).unwrap();

        let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("schemas")
            .join("technique.schema.json");

        write_spec(&spec_dir, "bad.yaml", "id: 1\n");
        let err = list_saf_mcp_techniques(&spec_dir, &schema_path, None).unwrap_err();
        assert!(err.contains("validation failed"));
    }

    #[tokio::test]
    async fn scans_with_local_model() {
        let dir = tempdir().unwrap();

        // Spec dir with valid technique
        let spec_dir = dir.path().join("specs");
        std::fs::create_dir_all(&spec_dir).unwrap();
        let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("schemas")
            .join("technique.schema.json");
        let t = r#"
id: "T1001"
name: "Technique"
severity: "P1"
summary: "S"
description: "D"
mitigations:
  - id: "M1"
    description: "Mit"
code_signals:
  - id: "S1"
    description: "Sig"
    heuristics:
      - pattern: "foo"
languages: ["rust"]
output_schema:
  requires_mitigations: false
  allowed_status_values: ["pass","fail"]
"#;
        write_spec(&spec_dir, "t.yaml", t);

        // SAF-MCP corpus
        let saf_root = dir.path().join("saf-mcp");
        let tech_root = saf_root.join("techniques");
        let mitigations_root = saf_root.join("mitigations");
        std::fs::create_dir_all(tech_root.join("T1001")).unwrap();
        std::fs::create_dir_all(mitigations_root.join("SAF-M-1")).unwrap();
        std::fs::write(tech_root.join("T1001/README.md"), "# T1001\nDetails").unwrap();
        std::fs::write(
            saf_root.join("README.md"),
            "| Tactic ID | Tactic Name | Technique ID | Technique Name | Description |\n|-----------|-------------|--------------|----------------|-------------|\n| ATK-TA0001 | Initial Access | T1001 | Technique | Desc |\n",
        )
        .unwrap();
        std::fs::write(
            tech_root.join("prioritized-techniques.md"),
            "| Technique ID | Name |\n| SAF-T1001 | Technique |\n",
        )
        .unwrap();
        std::fs::write(
            mitigations_root.join("SAF-M-1/README.md"),
            "# Mitigation\n",
        )
        .unwrap();

        // Repo under scan
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("main.rs"), "fn main() { let foo = 1; }").unwrap();

        let args = ScanArgs {
            technique_id: "T1001".into(),
            repo_path: repo.clone(),
            spec_dir: spec_dir.clone(),
            schema_path: schema_path.clone(),
            saf_mcp_root: saf_root.clone(),
            scope: engine::chunk::ScopeKind::FullRepo,
            max_lines_per_chunk: 200,
            filters: None,
            provider: Provider::Local,
            model_name: None,
            config: None,
        };

        let result = handle_scan_technique(args).await.unwrap();
        assert_eq!(result.analysis.findings.len(), 1);
    }

    #[test]
    fn resolves_workspace_paths_and_blocks_escape() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        // Create parent to allow canonicalization.
        std::fs::create_dir_all(root.join("a")).unwrap();
        // Create the file to allow canonicalization in all environments.
        std::fs::write(root.join("a/b.txt"), "x").unwrap();
        let allowed_rel = resolve_workspace_path(root, "a/b.txt").unwrap();
        assert!(allowed_rel.starts_with(root.canonicalize().unwrap()));

        let escape = resolve_workspace_path(root, "../outside.txt");
        assert!(escape.is_err());
    }

    #[test]
    fn max_file_bytes_zero_disables_filter() {
        let params = ScanParams {
            technique_id: "T1".into(),
            path: Some("/tmp/repo".into()),
            repo_path: None,
            spec_dir: None,
            schema_path: None,
            saf_mcp_root: None,
            scope: None,
            file: None,
            selection: None,
            base_ref: None,
            max_lines_per_chunk: None,
            include_extensions: None,
            exclude_extensions: None,
            include_globs: None,
            exclude_globs: None,
            max_file_bytes: Some(0),
            provider: None,
            model_name: None,
            config: None,
        };
        let dummy_cfg = engine::config::Config {
            allow_remote_providers: false,
            allowed_providers: None,
            model_names: None,
            openai_api_key: None,
            anthropic_api_key: None,
            retry_max_retries: None,
            retry_delay_ms: None,
            timeout_ms: None,
            include_extensions: None,
            exclude_extensions: None,
            include_globs: None,
            exclude_globs: None,
            max_file_bytes: None,
        };
        let filters = parse_filters(&params, &dummy_cfg).unwrap();
        assert!(filters.max_file_bytes.is_none());

        let params_with_limit = ScanParams {
            max_file_bytes: Some(1024),
            ..params
        };
        let dummy_cfg = engine::config::Config {
            allow_remote_providers: false,
            allowed_providers: None,
            model_names: None,
            openai_api_key: None,
            anthropic_api_key: None,
            retry_max_retries: None,
            retry_delay_ms: None,
            timeout_ms: None,
            include_extensions: None,
            exclude_extensions: None,
            include_globs: None,
            exclude_globs: None,
            max_file_bytes: None,
        };
        let filters = parse_filters(&params_with_limit, &dummy_cfg).unwrap();
        assert_eq!(filters.max_file_bytes, Some(1024));
    }

    #[test]
    fn mcp_tools_include_all() {
        let tools = mcp_tools();
        let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
        for expected in [
            "list_saf_mcp_techniques",
            "scan_technique",
            "explain_finding",
            "propose_mitigation_patch",
        ] {
            assert!(
                names.contains(&expected.to_string()),
                "missing tool {} in {:?}",
                expected,
                names
            );
        }
    }
}
