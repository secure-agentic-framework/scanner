use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use engine::{
    adapters::{anthropic::AnthropicModel, local::LocalModel, openai::OpenAIModel},
    chunk::ScopeKind,
    config::{enforce_provider_allowlist, load_config},
    entrypoint::analyze_technique,
};
use serde::Serialize;
use reqwest::StatusCode;

#[derive(Parser, Debug)]
#[command(
    name = "saf-mcp-scan",
    about = "Run SAF-MCP technique scans against a repo"
)]
struct Args {
    /// Technique ID to scan (e.g., SAF-T1001)
    technique_id: String,
    /// Path to repository to scan
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Directory containing technique spec YAML/JSON files
    #[arg(long, default_value = "techniques")]
    spec_dir: PathBuf,
    /// Path to technique JSON schema
    #[arg(long, default_value = "schemas/technique.schema.json")]
    schema: PathBuf,
    /// Path to SAF-MCP corpus root (with techniques/, mitigations/, README.md)
    #[arg(long, default_value = "saf-mcp")]
    saf_mcp: PathBuf,
    /// Max lines per chunk
    #[arg(long, default_value_t = 200)]
    max_lines_per_chunk: usize,
    /// Scope for scanning
    #[arg(long, default_value = "full")]
    scope: ScopeArg,
    /// File to scan (required for --scope file/selection)
    #[arg(long)]
    file: Option<PathBuf>,
    /// Selection in the form <path>:<start>-<end> (required for --scope selection)
    #[arg(long)]
    selection: Option<String>,
    /// Base ref for git diff scope (not yet implemented; treated as full repo)
    #[arg(long)]
    git_diff: Option<String>,
    /// Model provider: local|openai|anthropic
    #[arg(long, default_value = "local")]
    provider: ProviderArg,
    /// Model name override (provider-specific)
    #[arg(long)]
    model_name: Option<String>,
    /// Config file path (YAML/JSON)
    #[arg(long)]
    config: Option<PathBuf>,
    /// Include file extensions (comma-separated, e.g. rs,py)
    #[arg(long)]
    include_ext: Option<String>,
    /// Exclude file extensions (comma-separated, e.g. md,txt)
    #[arg(long)]
    exclude_ext: Option<String>,
    /// Include glob patterns (comma-separated)
    #[arg(long)]
    include_glob: Option<String>,
    /// Exclude glob patterns (comma-separated)
    #[arg(long)]
    exclude_glob: Option<String>,
    /// Max file size in bytes (0 = no limit)
    #[arg(long)]
    max_file_bytes: Option<u64>,
    /// Output JSON instead of human-readable summary
    #[arg(long)]
    json: bool,
    /// Perform a second-pass LLM review to filter findings (OpenAI only)
    #[arg(long)]
    llm_review: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ScopeArg {
    Full,
    File,
    Selection,
    GitDiff,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum ProviderArg {
    Local,
    Openai,
    Anthropic,
}

#[derive(Serialize)]
struct OutputFinding {
    chunk_id: String,
    file: String,
    start_line: usize,
    end_line: usize,
    severity: String,
    observation: String,
    evidence: String,
    model_support: Vec<String>,
    unknown_mitigations: Vec<String>,
}

#[derive(Serialize)]
struct OutputAnalysis {
    status: String,
    summary: String,
    findings: Vec<OutputFinding>,
    model_support: Vec<String>,
    scanned_at_utc: String,
    files_scanned: usize,
    chunks_analyzed: usize,
}

#[derive(Serialize)]
struct OutputEnvelope {
    analysis: OutputAnalysis,
    missing_techniques: Vec<String>,
    extra_techniques: Vec<String>,
    mitigation_titles: Vec<(String, String)>,
    readme_path: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    match run(args).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

async fn run(args: Args) -> Result<i32, String> {
    let scope = build_scope(&args)?;
    let cfg = load_config(args.config.as_deref()).map_err(|e| format!("config error: {e}"))?;

    let saf_mcp_techniques = args.saf_mcp.join("techniques");
    let mitigations_dir = args.saf_mcp.join("mitigations");
    let prioritized_path = saf_mcp_techniques.join("prioritized-techniques.md");
    let readme_path = args.saf_mcp.join("README.md");
    let cli_max_provided = args.max_file_bytes.is_some();
    let filters = build_filters(&args);
    let filters = merge_filters_with_config(filters, &cfg, cli_max_provided);

    let model = build_model(&args, &cfg)?;
    let mut result = analyze_technique(
        &model,
        &args.technique_id,
        &args.repo,
        &args.spec_dir,
        &args.schema,
        &mitigations_dir,
        &saf_mcp_techniques,
        &prioritized_path,
        &readme_path,
        scope,
        args.max_lines_per_chunk,
        Some(filters),
    )
    .await?;
    result.analysis = post_process_findings(&args.technique_id, result.analysis);
    if args.llm_review {
        if let Some(reviewed) = run_llm_review(&args, &result, &cfg).await? {
            result.analysis = reviewed;
        }
    }

    if args.json {
        let output = to_output(&result)?;
        let json = serde_json::to_string_pretty(&output).map_err(|e| e.to_string())?;
        println!("{json}");
    } else {
        print_human(&result);
    }

    let exit_code = match result.analysis.status {
        engine::status::AnalysisStatus::Fail | engine::status::AnalysisStatus::Unknown => 1,
        _ => 0,
    };
    Ok(exit_code)
}

fn post_process_findings(
    technique_id: &str,
    mut analysis: engine::status::AnalysisResult,
) -> engine::status::AnalysisResult {
    let status = engine::status::compute_status(&analysis.findings);
    let summary = engine::status::summarize(technique_id, &status, &analysis.findings);
    analysis.status = status;
    analysis.summary = summary;
    analysis
}

async fn run_llm_review(
    args: &Args,
    output: &engine::entrypoint::AnalyzeOutput,
    cfg: &engine::config::Config,
) -> Result<Option<engine::status::AnalysisResult>, String> {
    if args.provider != ProviderArg::Openai {
        return Ok(None);
    }
    let api_key = cfg
        .openai_api_key
        .clone()
        .ok_or_else(|| "OPENAI_API_KEY not set in config or env".to_string())?;
    let findings = &output.analysis.findings;
    if findings.is_empty() {
        return Ok(None);
    }
    let payload = serde_json::json!({
        "technique_id": args.technique_id,
        "summary": output.analysis.summary,
        "findings": findings,
        "readme_path": output.readme_path,
    });
    let review_model = args
        .model_name
        .clone()
        .or_else(|| cfg.model_names.clone().and_then(|m| m.get(0).cloned()))
        .unwrap_or_else(|| "gpt-4o-mini".to_string());
    let body = serde_json::json!({
        "model": review_model,
        "response_format": { "type": "json_object" },
        "messages": [
            { "role": "system", "content": "You are a security reviewer. Given technique_id and initial findings, return JSON {\"findings\":[...]} keeping only code-backed, technique-relevant items. Use the original file/line/evidence; do not invent new findings."},
            { "role": "user", "content": payload.to_string() }
        ]
    });
    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.openai.com/v1/chat/completions")
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("review call failed: {e}"))?;
    if resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        eprintln!(
            "llm review call failed with status {}; keeping original findings",
            resp.status()
        );
        return Ok(None);
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("review parse failed: {e}"))?;
    let content = match v["choices"][0]["message"]["content"].as_str() {
        Some(s) => s,
        None => {
            eprintln!("llm review missing content, keeping original findings");
            return Ok(None);
        }
    };
    let reviewed: serde_json::Value = match serde_json::from_str(content) {
        Ok(val) => val,
        Err(e) => {
            eprintln!("llm review json parse failed: {e}; keeping original findings");
            return Ok(None);
        }
    };
    let findings_value = match reviewed.get("findings") {
        Some(v) => v,
        None => {
            eprintln!("llm review response missing findings; keeping original findings");
            return Ok(None);
        }
    };
    let findings: Vec<engine::aggregation::Finding> = match serde_json::from_value(findings_value.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("llm review findings parse failed: {e}; keeping original findings");
            return Ok(None);
        }
    };
    let status = engine::status::compute_status(&findings);
    let summary = engine::status::summarize(&args.technique_id, &status, &findings);
    let mut analysis = output.analysis.clone();
    analysis.findings = findings;
    analysis.status = status;
    analysis.summary = summary;
    // Recompute model_support to reflect the filtered findings
    let mut support = Vec::new();
    for f in &analysis.findings {
        for m in &f.model_support {
            if !support.contains(m) {
                support.push(m.clone());
            }
        }
    }
    analysis.model_support = support;
    Ok(Some(analysis))
}

fn build_model(args: &Args, cfg: &engine::config::Config) -> Result<ModelBox, String> {
    match args.provider {
        ProviderArg::Local => {
            enforce_provider_allowlist(cfg, "local")?;
            Ok(ModelBox(Box::new(LocalModel::default())))
        }
        ProviderArg::Openai => {
            enforce_provider_allowlist(cfg, "openai")?;
            let key = cfg
                .openai_api_key
                .clone()
                .ok_or_else(|| "OPENAI_API_KEY not set in config or env".to_string())?;
            let name = args
                .model_name
                .clone()
                .or_else(|| cfg.model_names.clone().and_then(|m| m.get(0).cloned()))
                .unwrap_or_else(|| "gpt-4o-mini".to_string());
            Ok(ModelBox(Box::new(OpenAIModel::new(name, key, cfg.openai_base_url.clone()))))
        }
        ProviderArg::Anthropic => {
            enforce_provider_allowlist(cfg, "anthropic")?;
            let key = cfg
                .anthropic_api_key
                .clone()
                .ok_or_else(|| "ANTHROPIC_API_KEY not set in config or env".to_string())?;
            let name = args
                .model_name
                .clone()
                .or_else(|| cfg.model_names.clone().and_then(|m| m.get(0).cloned()))
                .unwrap_or_else(|| "claude-3-5-sonnet-20240620".to_string());
            Ok(ModelBox(Box::new(AnthropicModel::new(name, key))))
        }
    }
}

struct ModelBox(Box<dyn engine::codemodel::CodeModel + Send + Sync>);

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

fn build_filters(args: &Args) -> engine::chunk::PathFilters {
    engine::chunk::PathFilters {
        include_extensions: split_list_lower(args.include_ext.as_deref()),
        exclude_extensions: split_list_lower(args.exclude_ext.as_deref()),
        include_globs: split_list_raw(args.include_glob.as_deref()),
        exclude_globs: split_list_raw(args.exclude_glob.as_deref()),
        // Preserve explicit CLI value, including 0, so we can override config later.
        max_file_bytes: args.max_file_bytes,
        exclude_docs: false,
    }
}

fn merge_filters_with_config(
    filters: engine::chunk::PathFilters,
    cfg: &engine::config::Config,
    cli_max_provided: bool,
) -> engine::chunk::PathFilters {
    let cfg_max = match cfg.max_file_bytes {
        Some(0) => None,
        other => other,
    };
    engine::chunk::PathFilters {
        include_extensions: if !filters.include_extensions.is_empty() {
            filters.include_extensions
        } else {
            cfg.include_extensions.clone().unwrap_or_default()
        },
        exclude_extensions: if !filters.exclude_extensions.is_empty() {
            filters.exclude_extensions
        } else {
            cfg.exclude_extensions.clone().unwrap_or_default()
        },
        include_globs: if !filters.include_globs.is_empty() {
            filters.include_globs
        } else {
            cfg.include_globs.clone().unwrap_or_default()
        },
        exclude_globs: if !filters.exclude_globs.is_empty() {
            filters.exclude_globs
        } else {
            cfg.exclude_globs.clone().unwrap_or_default()
        },
        max_file_bytes: if cli_max_provided {
            match filters.max_file_bytes {
                Some(0) => None,
                other => other,
            }
        } else {
            cfg_max
        },
        exclude_docs: false,
    }
}

fn split_list_lower(raw: Option<&str>) -> Vec<String> {
    raw.map(|s| {
        s.split(',')
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .map(|x| x.to_lowercase())
            .collect()
    })
    .unwrap_or_default()
}

fn split_list_raw(raw: Option<&str>) -> Vec<String> {
    raw.map(|s| {
        s.split(',')
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .map(|x| x.to_string())
            .collect()
    })
    .unwrap_or_default()
}

fn build_scope(args: &Args) -> Result<ScopeKind, String> {
    match args.scope {
        ScopeArg::Full => Ok(ScopeKind::FullRepo),
        ScopeArg::File => {
            let file = args
                .file
                .clone()
                .ok_or_else(|| "--file is required when --scope file".to_string())?;
            Ok(ScopeKind::File { file })
        }
        ScopeArg::Selection => {
            let selection = args
                .selection
                .as_ref()
                .ok_or_else(|| "--selection is required when --scope selection".to_string())?;
            parse_selection(selection)
        }
        ScopeArg::GitDiff => {
            let base = args.git_diff.clone().unwrap_or_else(|| "HEAD".to_string());
            Ok(ScopeKind::GitDiff { base_ref: base })
        }
    }
}

fn parse_selection(raw: &str) -> Result<ScopeKind, String> {
    let (path, range) = raw
        .split_once(':')
        .ok_or_else(|| "selection must be <path>:<start>-<end>".to_string())?;
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| "selection must be <path>:<start>-<end>".to_string())?;
    let start_line: usize = start
        .parse()
        .map_err(|_| "selection start must be a number".to_string())?;
    let end_line: usize = end
        .parse()
        .map_err(|_| "selection end must be a number".to_string())?;
    Ok(ScopeKind::Selection {
        file: PathBuf::from(path),
        start_line,
        end_line,
    })
}

fn status_str(status: &engine::status::AnalysisStatus) -> &'static str {
    match status {
        engine::status::AnalysisStatus::Pass => "pass",
        engine::status::AnalysisStatus::Fail => "fail",
        engine::status::AnalysisStatus::Partial => "partial",
        engine::status::AnalysisStatus::Unknown => "unknown",
    }
}

fn to_output(result: &engine::entrypoint::AnalyzeOutput) -> Result<OutputEnvelope, String> {
    let analysis = OutputAnalysis {
        status: status_str(&result.analysis.status).to_string(),
        summary: result.analysis.summary.clone(),
        findings: result
            .analysis
            .findings
            .iter()
            .map(|f| OutputFinding {
                chunk_id: f.chunk_id.clone(),
                file: f.file.clone(),
                start_line: f.start_line,
                end_line: f.end_line,
                severity: f.severity.clone(),
                observation: f.observation.clone(),
                evidence: f.evidence.clone(),
                model_support: f.model_support.clone(),
                unknown_mitigations: f.unknown_mitigations.clone(),
            })
            .collect(),
        model_support: result.analysis.model_support.clone(),
        scanned_at_utc: result.analysis.meta.scanned_at_utc.clone(),
        files_scanned: result.analysis.meta.files_scanned,
        chunks_analyzed: result.analysis.meta.chunks_analyzed,
    };

    Ok(OutputEnvelope {
        analysis,
        missing_techniques: result.missing_techniques.clone(),
        extra_techniques: result.extra_techniques.clone(),
        mitigation_titles: result.mitigation_titles.clone(),
        readme_path: result.readme_path.clone(),
    })
}

fn print_human(result: &engine::entrypoint::AnalyzeOutput) {
    let analysis = &result.analysis;
    println!("Status : {}", status_str(&analysis.status));
    println!("Summary: {}", analysis.summary);
    println!(
        "Scanned: {} files, {} chunks at {}",
        analysis.meta.files_scanned, analysis.meta.chunks_analyzed, analysis.meta.scanned_at_utc
    );
    println!("Technique README: {}", result.readme_path);
    if !result.mitigation_titles.is_empty() {
        println!("Mitigations:");
        for (id, title) in &result.mitigation_titles {
            println!("- {}: {}", id, title);
        }
    }
    println!("Findings: {}", analysis.findings.len());
    for f in &analysis.findings {
        println!(
            "- [{}] {}:{}-{} {} (models: {})",
            f.severity,
            f.file,
            f.start_line,
            f.end_line,
            f.observation,
            f.model_support.join(", ")
        );
    }
}
