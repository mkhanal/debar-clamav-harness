use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Inputs {
    root: PathBuf,
    relative_paths: Vec<PathBuf>,
}

#[derive(Debug)]
pub enum InputsError {
    Unreadable { path: PathBuf, error: io::Error },
    NoFiles { path: PathBuf },
}

impl Inputs {
    pub fn find(path: &Path) -> Result<Self, InputsError> {
        let unreadable = |error| InputsError::Unreadable {
            path: path.to_owned(),
            error,
        };
        let absolute = path.canonicalize().map_err(unreadable)?;
        let (root, mut relative_paths) = if absolute.is_dir() {
            let mut files = Vec::new();
            collect_files(&absolute, Path::new(""), &mut files)?;
            (absolute, files)
        } else {
            let root = absolute.parent().map_or_default(Path::to_path_buf);
            let name = absolute.file_name().map_or_default(PathBuf::from);
            (root, vec![name])
        };
        if relative_paths.is_empty() {
            return Err(InputsError::NoFiles {
                path: path.to_owned(),
            });
        }
        relative_paths.sort();
        Ok(Self {
            root,
            relative_paths,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn relative_paths(&self) -> &[PathBuf] {
        &self.relative_paths
    }
}

fn collect_files(
    root: &Path,
    relative: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), InputsError> {
    let directory = root.join(relative);
    let unreadable = |error| InputsError::Unreadable {
        path: directory.clone(),
        error,
    };
    for entry in fs::read_dir(&directory).map_err(unreadable)? {
        let entry = entry.map_err(unreadable)?;
        let kind = entry.file_type().map_err(unreadable)?;
        let entry_relative = relative.join(entry.file_name());
        if kind.is_dir() {
            collect_files(root, &entry_relative, files)?;
        } else if kind.is_file() {
            files.push(entry_relative);
        }
    }
    Ok(())
}

impl fmt::Display for InputsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { path, error } => {
                write!(
                    formatter,
                    "cannot read the input {}: {error}",
                    path.display()
                )
            }
            Self::NoFiles { path } => {
                write!(
                    formatter,
                    "the input {} holds no file to scan",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for InputsError {}
