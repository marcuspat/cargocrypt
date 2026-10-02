//! Obtaining a password without mangling or leaking it.

use crate::error::{CargoCryptError, CryptoResult};
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

/// Environment variable holding the path of a password file.
pub const PASSWORD_FILE_ENV: &str = "CARGOCRYPT_PASSWORD_FILE";

/// Environment variable holding the password itself.
pub const PASSWORD_ENV: &str = "CARGOCRYPT_PASSWORD";

/// Remove exactly one trailing line ending.
///
/// Nothing else is touched: leading, trailing and interior whitespace are
/// part of the password. Trimming it silently weakens a passphrase and makes
/// the same password behave differently when typed and when piped.
pub fn strip_line_ending(mut text: String) -> Zeroizing<String> {
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    Zeroizing::new(text)
}

fn reject_empty(password: Zeroizing<String>, source: &str) -> CryptoResult<Zeroizing<String>> {
    if password.is_empty() {
        return Err(CargoCryptError::Config {
            message: format!("The password read from {} is empty", source),
            suggestion: None,
        });
    }
    Ok(password)
}

/// Read a password from a file: its contents minus one trailing newline.
pub fn read_password_file<P: AsRef<Path>>(path: P) -> CryptoResult<Zeroizing<String>> {
    let path = path.as_ref();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            eprintln!(
                "warning: password file {} is readable by other users (mode {:o}); run `chmod 600` on it",
                path.display(),
                mode & 0o777
            );
        }
    }

    let text = Zeroizing::new(std::fs::read_to_string(path)?);
    reject_empty(
        strip_line_ending(text.as_str().to_owned()),
        &path.display().to_string(),
    )
}

/// Read a password from a reader (standard input): everything up to the
/// first newline.
pub fn read_password_line<R: Read>(reader: R) -> CryptoResult<Zeroizing<String>> {
    use std::io::BufRead;
    let mut line = String::new();
    std::io::BufReader::new(reader).read_line(&mut line)?;
    reject_empty(strip_line_ending(line), "standard input")
}

/// The password for non-interactive use, from the environment:
/// `CARGOCRYPT_PASSWORD_FILE` first, then `CARGOCRYPT_PASSWORD`.
pub fn from_environment() -> CryptoResult<Option<Zeroizing<String>>> {
    if let Some(path) = std::env::var_os(PASSWORD_FILE_ENV).filter(|p| !p.is_empty()) {
        return read_password_file(path).map(Some);
    }
    match std::env::var(PASSWORD_ENV) {
        Ok(password) if !password.is_empty() => Ok(Some(Zeroizing::new(password))),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_line_ending_is_removed() {
        assert_eq!(
            strip_line_ending("pass word \n".into()).as_str(),
            "pass word "
        );
        assert_eq!(strip_line_ending("pw\r\n".into()).as_str(), "pw");
        assert_eq!(strip_line_ending("pw\n\n".into()).as_str(), "pw\n");
        assert_eq!(strip_line_ending("  pw".into()).as_str(), "  pw");
        assert_eq!(strip_line_ending("pw".into()).as_str(), "pw");
    }

    #[test]
    fn stdin_line_keeps_its_whitespace() {
        let password = read_password_line(&b"  two  spaces \nignored second line\n"[..]).unwrap();
        assert_eq!(password.as_str(), "  two  spaces ");
    }

    #[test]
    fn empty_input_is_an_error() {
        assert!(read_password_line(&b""[..]).is_err());
        assert!(read_password_line(&b"\n"[..]).is_err());
    }

    #[test]
    fn password_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pw");
        std::fs::write(&path, " correct horse \n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            read_password_file(&path).unwrap().as_str(),
            " correct horse "
        );

        std::fs::write(&path, "").unwrap();
        assert!(read_password_file(&path).is_err());
        assert!(read_password_file(dir.path().join("missing")).is_err());
    }
}
