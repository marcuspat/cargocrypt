//! Atomic, owner-only file output.

use rand::{rngs::OsRng, TryRngCore};
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// A file that only appears at its destination once it is complete.
///
/// Data is written to a randomly named sibling created with mode `0600`,
/// flushed to disk, then renamed over the destination. If the value is dropped
/// without [`AtomicFile::commit`], the temporary file is removed, so a failed
/// or interrupted operation leaves neither a partial output nor a stray
/// temporary behind.
pub struct AtomicFile {
    file: Option<File>,
    temp_path: PathBuf,
    destination: PathBuf,
}

impl AtomicFile {
    /// Start writing a file that will end up at `destination`.
    pub fn create<P: AsRef<Path>>(destination: P) -> io::Result<Self> {
        let destination = destination.as_ref().to_path_buf();
        let directory = match destination.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let name = destination
            .file_name()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "destination has no file name")
            })?
            .to_string_lossy()
            .into_owned();

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        // `create_new` refuses to follow or reuse an existing path, so a
        // collision (or a planted symlink) is an error rather than a clobber.
        for _ in 0..16 {
            let temp_path =
                directory.join(format!(".{}.{:016x}.tmp", name, OsRng.try_next_u64().unwrap()));
            match options.open(&temp_path) {
                Ok(file) => {
                    return Ok(Self {
                        file: Some(file),
                        temp_path,
                        destination,
                    })
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique temporary file",
        ))
    }

    /// The file to write to.
    pub fn file(&mut self) -> &mut File {
        self.file.as_mut().expect("file is present until commit")
    }

    /// Flush to disk and move the file into place.
    pub fn commit(mut self) -> io::Result<()> {
        let file = self.file.take().expect("file is present until commit");
        file.sync_all()?;
        drop(file);
        std::fs::rename(&self.temp_path, &self.destination)?;

        // Persist the rename itself. Best effort: not every platform or
        // filesystem lets a directory be opened and synced.
        #[cfg(unix)]
        if let Some(parent) = self.destination.parent() {
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        if self.file.take().is_some() {
            let _ = std::fs::remove_file(&self.temp_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn commit_moves_the_file_into_place() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out.bin");
        std::fs::write(&dest, b"old").unwrap();

        let mut atomic = AtomicFile::create(&dest).unwrap();
        atomic.file().write_all(b"new contents").unwrap();
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"old",
            "visible before commit"
        );
        atomic.commit().unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"new contents");
        assert_eq!(entries(dir.path()), vec!["out.bin"]);
    }

    #[test]
    fn dropping_without_commit_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out.bin");

        let mut atomic = AtomicFile::create(&dest).unwrap();
        atomic.file().write_all(b"partial").unwrap();
        drop(atomic);

        assert!(entries(dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn output_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out.bin");

        let mut atomic = AtomicFile::create(&dest).unwrap();
        atomic.file().write_all(b"secret").unwrap();
        atomic.commit().unwrap();

        let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
