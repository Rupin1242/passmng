//! File system helpers shared by the config and the vault.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Writes `data` to `path` atomically: the data goes to a temporary file in
/// the same directory first, which is then renamed over `path`. An
/// interrupted write therefore never leaves a half-written file behind.
///
/// The file is created with mode 0600 because both the vault and the config
/// are private to the user.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = temp_path(path)?;
    let result = write_and_rename(&tmp, path, data);
    if result.is_err() {
        // Best effort: do not leave the temporary file behind.
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn write_and_rename(tmp: &Path, path: &Path, data: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(tmp)
        .with_context(|| format!("failed to create {}", tmp.display()))?;
    file.write_all(data)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    drop(file);

    fs::rename(tmp, path)
        .with_context(|| format!("failed to rename {} to {}", tmp.display(), path.display()))?;

    // Persist the rename itself. Failing here is not fatal for correctness
    // of the content, so the error is ignored.
    if let Some(dir) = path.parent()
        && let Ok(dir) = File::open(dir)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Returns the temporary file path used while writing `path`
/// (e.g. `dir/vault.bin` -> `dir/.vault.bin.tmp`).
fn temp_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .with_context(|| format!("invalid file path: {}", path.display()))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(".tmp");
    Ok(path.with_file_name(tmp_name))
}

/// Creates `dir` and its missing parents. Newly created directories get mode
/// 0700 so that other users cannot list the vault directory.
pub fn create_private_dir_all(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("failed to create directory {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_creates_and_replaces_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");

        write_atomic(&path, b"first").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first");

        write_atomic(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");

        // Only the target file remains; the temporary file was renamed away.
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec!["file.bin"]);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_uses_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        write_atomic(&path, b"data").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn write_atomic_fails_when_directory_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing").join("file.bin");
        assert!(write_atomic(&path, b"data").is_err());
    }

    #[test]
    fn temp_path_is_hidden_sibling() {
        assert_eq!(
            temp_path(Path::new("/a/b/vault.bin")).unwrap(),
            PathBuf::from("/a/b/.vault.bin.tmp")
        );
    }

    #[cfg(unix)]
    #[test]
    fn create_private_dir_all_creates_nested_private_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        create_private_dir_all(&nested).unwrap();
        let mode = fs::metadata(&nested).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        // Calling it again on an existing directory is fine.
        create_private_dir_all(&nested).unwrap();
    }
}
