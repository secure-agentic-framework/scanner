use crate::TechniqueRef;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug)]
pub struct PrioritizedTechniques {
    pub techniques: Vec<TechniqueRef>, // in prioritized order from the file
    pub errors: Vec<PrioritizedParseError>,
}

#[derive(Debug, Error)]
pub enum PrioritizedParseError {
    #[error("failed to read prioritized techniques file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Parse techniques/prioritized-techniques.md to extract an ordered list of technique ids/names.
/// Expected rows like: "| SAF-T1001 | Tool Poisoning Attack |"
pub fn parse_prioritized_techniques<P: AsRef<Path>>(path: P) -> PrioritizedTechniques {
    let path_ref = path.as_ref();
    let content = match fs::read_to_string(path_ref) {
        Ok(c) => c,
        Err(e) => {
            return PrioritizedTechniques {
                techniques: vec![],
                errors: vec![PrioritizedParseError::Io {
                    path: path_ref.to_path_buf(),
                    source: e,
                }],
            }
        }
    };

    let row_re = Regex::new(r"(?m)^\|\s*(SAF-T\d+)\s*\|\s*([^|]+)\|").unwrap();
    let mut techniques: Vec<TechniqueRef> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for cap in row_re.captures_iter(&content) {
        let id = cap[1].trim().to_string();
        if !seen.insert(id.clone()) {
            continue;
        }
        let name = cap[2].trim().to_string();
        techniques.push(TechniqueRef { id, name });
    }

    PrioritizedTechniques {
        techniques,
        errors: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_prioritized(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join("prioritized-techniques.md");
        let mut f = File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn parses_ordered_list() {
        let dir = tempdir().unwrap();
        let path = write_prioritized(
            dir.path(),
            r#"| Technique ID | Name |
| SAF-T1002 | Supply Chain |
| SAF-T1001 | Tool Poisoning |
| SAF-T1102 | Prompt Injection |
| SAF-T1001 | Duplicate ignored |
"#,
        );

        let result = parse_prioritized_techniques(&path);
        assert!(result.errors.is_empty());
        let ids: Vec<_> = result.techniques.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, vec!["SAF-T1002", "SAF-T1001", "SAF-T1102"]);
        let names: Vec<_> = result.techniques.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["Supply Chain", "Tool Poisoning", "Prompt Injection"]
        );
    }

    #[test]
    fn reports_io_error() {
        let path = PathBuf::from("missing/prioritized-techniques.md");
        let result = parse_prioritized_techniques(&path);
        assert!(result.techniques.is_empty());
        assert_eq!(result.errors.len(), 1);
        assert!(matches!(result.errors[0], PrioritizedParseError::Io { .. }));
    }
}
