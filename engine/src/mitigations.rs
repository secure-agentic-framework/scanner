use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug)]
pub struct MitigationRef {
    pub id: String,
    pub title: String,
}

#[derive(Debug)]
pub struct MitigationIndex {
    pub mitigations: Vec<MitigationRef>,
    pub errors: Vec<MitigationIndexError>,
}

#[derive(Debug, Error)]
pub enum MitigationIndexError {
    #[error("failed to read mitigations directory {path}: {source}")]
    DirIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read mitigation file {path}: {source}")]
    FileIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Index mitigation IDs and titles from README.md files under a mitigations directory.
/// Expects each mitigation directory to contain a README with a top-level heading "# <title>".
pub fn index_mitigations<P: AsRef<Path>>(mitigations_dir: P) -> MitigationIndex {
    let mut mitigations = Vec::new();
    let mut errors = Vec::new();
    let dir = mitigations_dir.as_ref();

    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            errors.push(MitigationIndexError::DirIo {
                path: dir.to_path_buf(),
                source: err,
            });
            return MitigationIndex {
                mitigations,
                errors,
            };
        }
    };

    let heading_re = Regex::new(r"(?m)^#\s+(?P<title>.+)$").unwrap();

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                errors.push(MitigationIndexError::DirIo {
                    path: dir.to_path_buf(),
                    source: err,
                });
                continue;
            }
        };
        if !entry.file_type().map(|f| f.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name();
        let id = name.to_string_lossy().to_string();
        let readme_path = entry.path().join("README.md");
        let contents = match fs::read_to_string(&readme_path) {
            Ok(c) => c,
            Err(err) => {
                errors.push(MitigationIndexError::FileIo {
                    path: readme_path,
                    source: err,
                });
                continue;
            }
        };
        let title = heading_re
            .captures(&contents)
            .and_then(|cap| cap.name("title"))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_else(|| "Untitled".to_string());
        mitigations.push(MitigationRef { id, title });
    }

    mitigations.sort_by(|a, b| a.id.cmp(&b.id));
    MitigationIndex {
        mitigations,
        errors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_readme(dir: &Path, title: &str) {
        let path = dir.join("README.md");
        let mut f = File::create(path).unwrap();
        writeln!(f, "# {}", title).unwrap();
    }

    #[test]
    fn indexes_ids_and_titles() {
        let dir = tempdir().unwrap();
        let m1 = dir.path().join("SAF-M-1");
        let m2 = dir.path().join("SAF-M-2");
        fs::create_dir(&m1).unwrap();
        fs::create_dir(&m2).unwrap();
        write_readme(&m1, "Mitigation One");
        write_readme(&m2, "Mitigation Two");

        let index = index_mitigations(dir.path());
        assert!(index.errors.is_empty());
        let ids: Vec<_> = index.mitigations.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["SAF-M-1", "SAF-M-2"]);
        let titles: Vec<_> = index.mitigations.iter().map(|m| m.title.as_str()).collect();
        assert_eq!(titles, vec!["Mitigation One", "Mitigation Two"]);
    }

    #[test]
    fn reports_missing_readme() {
        let dir = tempdir().unwrap();
        let m1 = dir.path().join("SAF-M-1");
        fs::create_dir(&m1).unwrap();
        let index = index_mitigations(dir.path());
        assert_eq!(index.mitigations.len(), 0);
        assert_eq!(index.errors.len(), 1);
        match &index.errors[0] {
            MitigationIndexError::FileIo { path, .. } => {
                assert!(path.ends_with("SAF-M-1/README.md"));
            }
            _ => panic!("expected file IO error"),
        }
    }
}
