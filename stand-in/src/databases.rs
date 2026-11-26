use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use harness_report::DatabaseVersion;

const SIGNED_CONTAINER_EXTENSIONS: [&str; 2] = ["cvd", "cld"];
const HEADER_LENGTH: u64 = 512;
const HEADER_MAGIC: &str = "ClamAV-VDB";
const VERSION_FIELD: usize = 2;

pub fn versions_in(directory: &Path) -> Result<Vec<DatabaseVersion>, String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot list {}: {error}", directory.display()))?;
    let mut versions = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| format!("cannot list {}: {error}", directory.display()))?
            .path();
        let is_container = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| SIGNED_CONTAINER_EXTENSIONS.contains(&extension));
        let name = path.file_stem().and_then(|stem| stem.to_str());
        if let (true, Some(name)) = (is_container, name) {
            versions.push(DatabaseVersion {
                name: name.to_owned(),
                version: header_version(&path)?,
            });
        }
    }
    versions.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(versions)
}

fn header_version(path: &Path) -> Result<u32, String> {
    let unreadable = || format!("cannot read the header version of {}", path.display());
    let mut header = String::new();
    File::open(path)
        .and_then(|file| file.take(HEADER_LENGTH).read_to_string(&mut header))
        .map_err(|error| format!("{}: {error}", unreadable()))?;
    let mut fields = header.split(':');
    if fields.next() != Some(HEADER_MAGIC) {
        return Err(unreadable());
    }
    fields
        .nth(VERSION_FIELD.saturating_sub(1))
        .and_then(|field| field.parse().ok())
        .ok_or_else(unreadable)
}
