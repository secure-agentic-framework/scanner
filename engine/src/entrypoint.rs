use crate::{
    aggregation::{aggregate_findings, Finding},
    analysis::analyze_chunks,
    chunk::{build_chunks, ScopeKind},
    codemodel::CodeModel,
    mitigations::index_mitigations,
    prioritized::parse_prioritized_techniques,
    readme::{cross_check_readme_vs_dir, parse_readme_techniques},
    status::{build_analysis_result, AnalysisResult},
    validate_techniques,
};
use std::{fs, path::{Path, PathBuf}};

#[derive(Debug)]
pub struct AnalyzeOutput {
    pub analysis: AnalysisResult,
    pub missing_techniques: Vec<String>,
    pub extra_techniques: Vec<String>,
    pub mitigation_titles: Vec<(String, String)>,
    pub readme_path: String,
}

/// High-level entrypoint: load techniques, validate, build chunks, run model, aggregate, compute status.
pub async fn analyze_technique<M: CodeModel>(
    model: &M,
    technique_id: &str,
    repo_path: &Path,
    spec_dir: &Path,
    schema_path: &Path,
    mitigations_dir: &Path,
    saf_mcp_techniques_dir: &Path,
    prioritized_path: &Path,
    readme_path: &Path,
    scope: ScopeKind,
    max_lines_per_chunk: usize,
    filters: Option<crate::chunk::PathFilters>,
) -> Result<AnalyzeOutput, String> {
    let validation =
        validate_techniques(spec_dir, schema_path).map_err(|e| format!("schema error: {e}"))?;
    if let Some(err) = validation
        .errors
        .iter()
        .find(|e| e.path.to_string_lossy().contains(technique_id))
    {
        return Err(format!(
            "technique {} invalid: {:?}",
            technique_id, err.messages
        ));
    }
    let technique = validation
        .techniques
        .into_iter()
        .find(|t| t.id == technique_id)
        .ok_or_else(|| format!("technique {} not found", technique_id))?;

    let prioritized = parse_prioritized_techniques(prioritized_path);
    if !prioritized.errors.is_empty() {
        let msg = prioritized
            .errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("failed to parse prioritized techniques: {msg}"));
    }

    let readme = parse_readme_techniques(readme_path);
    if !readme.errors.is_empty() {
        let msg = readme
            .errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("failed to parse README techniques: {msg}"));
    }

    let mitigation_index = index_mitigations(mitigations_dir);
    if !mitigation_index.errors.is_empty() {
        let msg = mitigation_index
            .errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("failed to index mitigations: {msg}"));
    }

    let readme_path = resolve_technique_readme(saf_mcp_techniques_dir, technique_id)?;
    let readme_excerpt = fs::read_to_string(&readme_path)
        .map_err(|e| format!("failed to read technique README {}: {e}", readme_path.display()))?;

    let mut chunks =
        build_chunks(repo_path, &scope, max_lines_per_chunk, filters).map_err(|e| e.to_string())?;
    let model_findings = analyze_chunks(model, &technique, &mut chunks, Some(readme_excerpt))
        .await
        .map_err(|e| format!("model error: {e}"))?;
    let merged: Vec<Finding> = aggregate_findings(model_findings);
    let files_scanned = chunks.iter().map(|c| c.file.clone()).collect::<std::collections::HashSet<_>>().len();
    let chunks_analyzed = chunks.len();
    let analysis = build_analysis_result(technique_id, merged, files_scanned, chunks_analyzed)
        .map_err(|e| format!("analysis error: {e}"))?;

    let cross_check = cross_check_readme_vs_dir(&readme.techniques, saf_mcp_techniques_dir);
    if !cross_check.errors.is_empty() {
        let msg = cross_check.errors.join("; ");
        return Err(format!("failed to enumerate techniques directory: {msg}"));
    }

    let mitigation_titles = mitigation_index
        .mitigations
        .iter()
        .map(|m| (m.id.clone(), m.title.clone()))
        .collect();

    Ok(AnalyzeOutput {
        analysis,
        missing_techniques: cross_check.missing_in_dir,
        extra_techniques: cross_check.extra_in_dir,
        mitigation_titles,
        readme_path: readme_path.to_string_lossy().to_string(),
    })
}

fn resolve_technique_readme(
    techniques_root: &Path,
    technique_id: &str,
) -> Result<PathBuf, String> {
    let candidates = [
        techniques_root.join(technique_id).join("README.md"),
        techniques_root
            .join(format!("SAF-{technique_id}"))
            .join("README.md"),
        techniques_root
            .join(format!("SAF-{}", technique_id.trim_start_matches("SAF-")))
            .join("README.md"),
    ];
    for p in candidates {
        if p.exists() {
            return Ok(p);
        }
    }
    Err(format!(
        "technique README not found for {} under {} (tried {} and SAF-{})",
        technique_id,
        techniques_root.display(),
        techniques_root.join(technique_id).display(),
        techniques_root.join(format!("SAF-{technique_id}")).display()
    ))
}
