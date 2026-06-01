use crate::TechniqueRef;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug)]
pub struct ReadmeTechniques {
    pub techniques: Vec<TechniqueRef>,
    pub errors: Vec<ReadmeParseError>,
}

#[derive(Debug)]
pub struct CrossCheckReport {
    pub missing_in_dir: Vec<String>, // Present in README, missing in filesystem
    pub extra_in_dir: Vec<String>,   // Present on disk, missing in README
    pub errors: Vec<String>,         // IO errors during enumeration
}

#[derive(Debug, Error)]
pub enum ReadmeParseError {
    #[error("failed to read README at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Parse `saf-mcp/README.md` to extract technique ids and names from the TTP Overview table.
/// Returns sorted techniques (by id) and collects IO errors if the README cannot be read.
pub fn parse_readme_techniques<P: AsRef<Path>>(readme_path: P) -> ReadmeTechniques {
    let path = readme_path.as_ref();
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            return ReadmeTechniques {
                techniques: vec![],
                errors: vec![ReadmeParseError::Io {
                    path: path.to_path_buf(),
                    source: e,
                }],
            }
        }
    };

    // Matches rows like:
    // "| ATK-TA0001 | Initial Access | [SAF-T1002](techniques/SAF-T1002/README.md) | Supply Chain Compromise | ..."
    // "| ATK-TA0001 | Initial Access | SAF-T1004 | Server Impersonation | ..."
    // Handles linked and plain-text technique IDs by making the markdown link optional.
    let row_re = Regex::new(
        r"(?m)^\|\s*[^|]+\|\s*[^|]+\|\s*(?:\[(SAF-T\d+)\]\([^)]+\)|(SAF-T\d+))\s*\|\s*([^|]+)\|",
    )
    .unwrap();
    let mut seen = HashSet::new();
    let mut techniques: Vec<TechniqueRef> = Vec::new();
    for cap in row_re.captures_iter(&content) {
        let id = match cap.get(1).or_else(|| cap.get(2)) {
            Some(m) => m.as_str().trim().to_string(),
            None => continue,
        };
        if !seen.insert(id.clone()) {
            continue; // keep first occurrence from README order
        }
        let name = match cap.get(3) {
            Some(m) => m.as_str().trim().to_string(),
            None => continue,
        };
        techniques.push(TechniqueRef { id, name });
    }

    // Sort by id for stable downstream processing.
    techniques.sort_by(|a, b| a.id.cmp(&b.id));

    ReadmeTechniques {
        techniques,
        errors: vec![],
    }
}

/// Compare README-listed technique ids to directories/files under `techniques_dir`.
/// - missing_in_dir: ids present in README but no matching entry on disk.
/// - extra_in_dir: ids present on disk but not listed in README.
pub fn cross_check_readme_vs_dir<P: AsRef<Path>>(
    readme_techniques: &[TechniqueRef],
    techniques_dir: P,
) -> CrossCheckReport {
    let mut errors = Vec::new();
    let readme_ids: HashSet<String> = readme_techniques
        .iter()
        .map(|t| normalize_id(&t.id))
        .collect();

    let mut dir_ids = HashSet::new();
    match std::fs::read_dir(&techniques_dir) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(e) => {
                        let name = e.file_name();
                        let name = name.to_string_lossy();
                        if name.starts_with("SAF-T") {
                            dir_ids.insert(normalize_id(&name));
                        } else if name.starts_with('T') {
                            dir_ids.insert(name.to_string());
                        }
                    }
                    Err(err) => {
                        errors.push(format!(
                            "failed to read directory entry in {}: {}",
                            techniques_dir.as_ref().display(),
                            err
                        ));
                    }
                }
            }
        }
        Err(err) => errors.push(format!(
            "failed to read techniques directory {}: {}",
            techniques_dir.as_ref().display(),
            err
        )),
    }

    let mut missing_in_dir: Vec<String> = readme_ids.difference(&dir_ids).cloned().collect();
    let mut extra_in_dir: Vec<String> = dir_ids.difference(&readme_ids).cloned().collect();

    missing_in_dir.sort();
    extra_in_dir.sort();

    CrossCheckReport {
        missing_in_dir,
        extra_in_dir,
        errors,
    }
}

fn normalize_id(id: &str) -> String {
    if let Some(stripped) = id.strip_prefix("SAF-") {
        stripped.to_string()
    } else {
        id.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_readme(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join("README.md");
        let mut f = File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn parses_table_rows() {
        let dir = tempdir().unwrap();
        let path = write_readme(
            dir.path(),
            r#"| Tactic ID | Tactic Name | Technique ID | Technique Name | Description |
|-----------|-------------|--------------|----------------|-------------|
| ATK-TA0001 | Initial Access | [SAF-T1002](techniques/SAF-T1002/README.md) | Supply Chain Compromise | Desc |
| ATK-TA0001 | Initial Access | [SAF-T1001](techniques/SAF-T1001/README.md) | Tool Poisoning Attack (TPA) | Desc |
| ATK-TA0002 | Execution | [SAF-T1102](techniques/SAF-T1102/README.md) | Prompt Injection | Desc |
| ATK-TA0002 | Execution | SAF-T1104 | Over-Privileged Tool Abuse | Desc |
| ATK-TA0002 | Execution | SAF-T1104 | Different Name Should Be Ignored | Desc |
"#,
        );

        let result = parse_readme_techniques(&path);
        assert!(result.errors.is_empty());
        let ids: Vec<_> = result.techniques.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["SAF-T1001", "SAF-T1002", "SAF-T1102", "SAF-T1104"]
        );
        // Verify first occurrence wins for duplicate ids.
        let name_by_id = |id: &str| {
            result
                .techniques
                .iter()
                .find(|t| t.id == id)
                .map(|t| t.name.as_str())
                .unwrap()
        };
        assert_eq!(name_by_id("SAF-T1104"), "Over-Privileged Tool Abuse");
    }

    #[test]
    fn reports_io_error() {
        let path = PathBuf::from("does/not/exist/README.md");
        let result = parse_readme_techniques(&path);
        assert!(result.techniques.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert!(matches!(result.errors[0], ReadmeParseError::Io { .. }));
    }

    #[test]
    fn keeps_first_occurrence_on_duplicates() {
        let dir = tempdir().unwrap();
        let path = write_readme(
            dir.path(),
            r#"| Tactic ID | Tactic Name | Technique ID | Technique Name | Description |
|-----------|-------------|--------------|----------------|-------------|
| ATK-TA0001 | Initial Access | SAF-T1001 | First Name | Desc |
| ATK-TA0001 | Initial Access | SAF-T1001 | Second Name Should Be Ignored | Desc |
| ATK-TA0002 | Execution | SAF-T1101 | Other Technique | Desc |
"#,
        );

        let result = parse_readme_techniques(&path);
        assert!(result.errors.is_empty());
        assert_eq!(result.techniques.len(), 2);
        let first = result
            .techniques
            .iter()
            .find(|t| t.id == "SAF-T1001")
            .unwrap();
        assert_eq!(first.name, "First Name");
    }

    #[test]
    fn cross_check_reports_missing_and_extra() {
        let dir = tempdir().unwrap();
        let path = write_readme(
            dir.path(),
            r#"| Tactic ID | Tactic Name | Technique ID | Technique Name | Description |
|-----------|-------------|--------------|----------------|-------------|
| ATK-TA0001 | Initial Access | SAF-T1001 | Tool Poisoning | Desc |
| ATK-TA0001 | Initial Access | SAF-T1002 | Supply Chain | Desc |
"#,
        );
        let tech_dir = dir.path().join("techniques");
        std::fs::create_dir(&tech_dir).unwrap();
        std::fs::create_dir(tech_dir.join("SAF-T1002")).unwrap();
        std::fs::create_dir(tech_dir.join("SAF-T2000")).unwrap();

        let parsed = parse_readme_techniques(&path);
        let report = cross_check_readme_vs_dir(&parsed.techniques, &tech_dir);
        assert!(report.errors.is_empty());
        assert_eq!(report.missing_in_dir, vec!["T1001"]);
        assert_eq!(report.extra_in_dir, vec!["T2000"]);
    }
}
