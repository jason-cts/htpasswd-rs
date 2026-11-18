use std::{
    fs::{self, File, OpenOptions, Permissions},
    io::Write,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use tempfile::NamedTempFile;

use crate::AppError;

pub struct PasswordFile {
    path: PathBuf,
}

impl PasswordFile {
    pub fn open(path: &Path, must_exist: bool) -> Result<Self, AppError> {
        let path = match fs::metadata(path) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    return Err(AppError::new(1, "password file is not a regular file"));
                }
                fs::canonicalize(path).map_err(file_error)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !must_exist => {
                path.to_owned()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(AppError::new(
                    1,
                    format!("cannot open password file {}", path.display()),
                ));
            }
            Err(error) => return Err(file_error(error)),
        };
        Ok(Self { path })
    }

    pub fn add_or_update(
        &self,
        username: &str,
        hash: &str,
        create: bool,
    ) -> Result<&'static str, AppError> {
        let existing = fs::metadata(&self.path).ok();
        if let Some(metadata) = &existing {
            if !metadata.is_file() {
                return Err(AppError::new(1, "password file is not a regular file"));
            }
        } else if !create {
            return Err(AppError::new(
                1,
                format!(
                    "cannot modify file {}; use '-c' to create it",
                    self.path.display()
                ),
            ));
        }

        let original = if create {
            Vec::new()
        } else {
            self.read_write_contents()?
        };
        let mut output = Vec::with_capacity(original.len() + username.len() + hash.len() + 2);
        let mut found = false;
        for line in lines_with_endings(&original) {
            match record_username(line)? {
                Some(record_user) if record_user == username.as_bytes() => {
                    found = true;
                    output.extend_from_slice(username.as_bytes());
                    output.push(b':');
                    output.extend_from_slice(hash.as_bytes());
                    output.extend_from_slice(line_ending(line));
                }
                _ => output.extend_from_slice(line),
            }
        }

        let outcome = if found {
            "Updated"
        } else {
            if output.last().is_some_and(|last| *last != b'\n') {
                output.push(b'\n');
            }
            output.extend_from_slice(username.as_bytes());
            output.push(b':');
            output.extend_from_slice(hash.as_bytes());
            output.push(b'\n');
            "Added"
        };
        self.atomic_write(
            &output,
            existing.as_ref().map(|metadata| metadata.permissions()),
        )?;
        Ok(outcome)
    }

    pub fn delete(&self, username: &str) -> Result<bool, AppError> {
        let original = self.read_write_contents()?;
        let mut output = Vec::with_capacity(original.len());
        let mut found = false;
        for line in lines_with_endings(&original) {
            match record_username(line)? {
                Some(record_user) if record_user == username.as_bytes() => found = true,
                _ => output.extend_from_slice(line),
            }
        }
        if found {
            self.atomic_write(
                &output,
                Some(fs::metadata(&self.path).map_err(file_error)?.permissions()),
            )?;
        }
        Ok(found)
    }

    pub fn lookup_all(&self, username: &str) -> Result<Vec<String>, AppError> {
        let contents = fs::read(&self.path).map_err(file_error)?;
        let mut hashes = Vec::new();
        for line in lines_with_endings(&contents) {
            let Some(record_user) = record_username(line)? else {
                continue;
            };
            if record_user != username.as_bytes() {
                continue;
            }
            let colon = line
                .iter()
                .position(|byte| *byte == b':')
                .expect("record_username found the colon");
            let hash = trim_line_ending(&line[colon + 1..]);
            if hash.is_empty() {
                return Err(AppError::new(7, "empty password hash in password file"));
            }
            let hash = std::str::from_utf8(hash)
                .map_err(|_| AppError::new(7, "password hash is not valid UTF-8"))?;
            hashes.push(hash.to_owned());
        }
        Ok(hashes)
    }

    fn read_write_contents(&self) -> Result<Vec<u8>, AppError> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path)
            .map_err(file_error)?;
        fs::read(&self.path).map_err(file_error)
    }

    fn atomic_write(
        &self,
        contents: &[u8],
        permissions: Option<Permissions>,
    ) -> Result<(), AppError> {
        #[cfg(not(unix))]
        let _ = permissions;

        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let mut temporary = NamedTempFile::new_in(parent).map_err(file_error)?;
        temporary.write_all(contents).map_err(file_error)?;
        temporary.as_file().sync_all().map_err(file_error)?;

        #[cfg(unix)]
        {
            let mode = permissions
                .map(|permissions| permissions.mode() & 0o7777)
                .unwrap_or(0o600);
            temporary
                .as_file()
                .set_permissions(Permissions::from_mode(mode))
                .map_err(file_error)?;
        }

        temporary
            .persist(&self.path)
            .map_err(|error| file_error(error.error))?;
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    }
}

fn lines_with_endings(contents: &[u8]) -> impl Iterator<Item = &[u8]> {
    contents.split_inclusive(|byte| *byte == b'\n')
}

fn record_username(line: &[u8]) -> Result<Option<&[u8]>, AppError> {
    let line = trim_line_ending(line);
    let first = line
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(line.len());
    let line = &line[first..];
    if line.is_empty() || line[0] == b'#' {
        return Ok(None);
    }
    let colon = line
        .iter()
        .position(|byte| *byte == b':')
        .ok_or_else(|| AppError::new(7, "file does not appear to be a valid htpasswd file"))?;
    Ok(Some(&line[..colon]))
}

fn trim_line_ending(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\n")
        .unwrap_or(line)
        .strip_suffix(b"\r")
        .unwrap_or_else(|| line.strip_suffix(b"\n").unwrap_or(line))
}

fn line_ending(line: &[u8]) -> &'static [u8] {
    if line.ends_with(b"\r\n") {
        b"\r\n"
    } else if line.ends_with(b"\n") {
        b"\n"
    } else {
        b""
    }
}

fn file_error(error: std::io::Error) -> AppError {
    AppError::new(1, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write};

    use tempfile::tempdir;

    use super::PasswordFile;

    #[test]
    fn update_preserves_comments_unrelated_records_and_crlf() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("users.htpasswd");
        fs::write(&path, b"# team\r\nalice:old\r\nbob:keep\r\n").unwrap();
        let file = PasswordFile::open(&path, true).unwrap();

        assert_eq!(
            file.add_or_update("alice", "new", false).unwrap(),
            "Updated"
        );
        assert_eq!(
            fs::read(path).unwrap(),
            b"# team\r\nalice:new\r\nbob:keep\r\n"
        );
    }

    #[test]
    fn delete_removes_every_duplicate_and_missing_user_is_a_noop() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("users.htpasswd");
        fs::write(&path, b"alice:first\nbob:keep\nalice:second\n").unwrap();
        let file = PasswordFile::open(&path, true).unwrap();

        assert!(file.delete("alice").unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"bob:keep\n");
        assert!(!file.delete("missing").unwrap());
    }

    #[test]
    fn malformed_file_is_left_unchanged() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("users.htpasswd");
        fs::write(&path, b"valid:hash\nnot-a-record\n").unwrap();
        let before = fs::read(&path).unwrap();
        let file = PasswordFile::open(&path, true).unwrap();

        let error = file.add_or_update("new", "hash", false).unwrap_err();
        assert_eq!(error.exit_code, 7);
        assert_eq!(fs::read(path).unwrap(), before);
    }

    #[test]
    fn create_replaces_file_and_adds_the_requested_record() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("users.htpasswd");
        fs::write(&path, b"previous:record\n").unwrap();
        let file = PasswordFile::open(&path, true).unwrap();

        file.add_or_update("alice", "hash", true).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"alice:hash\n");
    }

    #[test]
    fn appends_after_a_file_without_a_final_newline() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("users.htpasswd");
        fs::File::create(&path)
            .unwrap()
            .write_all(b"alice:hash")
            .unwrap();
        let file = PasswordFile::open(&path, true).unwrap();

        file.add_or_update("bob", "other", false).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"alice:hash\nbob:other\n");
    }

    #[cfg(unix)]
    #[test]
    fn new_file_is_private_and_existing_mode_is_preserved() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempdir().unwrap();
        let path = directory.path().join("users.htpasswd");
        let new_file = PasswordFile::open(&path, false).unwrap();
        new_file.add_or_update("alice", "hash", true).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let alias = directory.path().join("alias.htpasswd");
        symlink(&path, &alias).unwrap();
        let through_alias = PasswordFile::open(&alias, true).unwrap();
        through_alias
            .add_or_update("alice", "updated", false)
            .unwrap();

        assert!(
            fs::symlink_metadata(&alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(fs::read_to_string(path).unwrap(), "alice:updated\n");
    }
}
