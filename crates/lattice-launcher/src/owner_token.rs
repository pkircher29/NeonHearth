//! Owner-token resolution for the launcher.
//!
//! The service keeps a rotated owner token in `<state_dir>/owner-token` and,
//! at startup, that file wins over the `LATTICE_SERVICE_TOKEN` environment
//! value (`choose_token` in `crates/lattice-service/src/main.rs`). The launcher
//! must use the same precedence or it keeps presenting the pre-rotation token.
//!
//! The validation rule duplicates `validate_token` in
//! `crates/lattice-service/src/state.rs` on purpose (the service crate is not a
//! dependency of the launcher): at least 32 bytes, at least 8 distinct bytes,
//! only `[A-Za-z0-9._-]`. Keep the two in step.
//!
//! The token value is never logged, formatted into an error, or returned in a
//! `Debug` representation: it only ever travels inside a `SecretString`.

use anyhow::{Result, bail};
use secrecy::SecretString;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// File name the service uses inside its state directory.
pub const OWNER_TOKEN_FILE: &str = "owner-token";
/// Far above any valid token; bounds what is read from an untrusted path.
const MAX_TOKEN_FILE_BYTES: usize = 4096;

/// Same acceptance rule as the service's `validate_token`.
pub fn is_valid_token(token: &str) -> bool {
    let distinct = token.bytes().collect::<BTreeSet<_>>().len();
    token.len() >= 32
        && distinct >= 8
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Token file of the service the portable launcher starts itself: the launcher
/// passes `LATTICE_STATE_BASE=<state>/data`, and the service appends
/// `NeonHearth` on Windows (`platform_paths`).
pub fn portable_token_file(state: &Path) -> PathBuf {
    state.join("data").join("NeonHearth").join(OWNER_TOKEN_FILE)
}

/// What a token-file read found. Carries the value only when it is usable.
pub enum TokenFile {
    Missing,
    /// Present but not readable (permissions, a directory, not UTF-8).
    Unreadable,
    /// Only whitespace: the service ignores such a file too.
    Empty,
    /// Too large, too short, too little variety or forbidden characters.
    Invalid,
    Present(SecretString),
}

/// Reads and validates a token file the way the service does: UTF-8, trimmed,
/// empty means "not set".
pub fn read_token_file(path: &Path) -> TokenFile {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return TokenFile::Missing,
        Err(_) => return TokenFile::Unreadable,
    };
    let mut bytes = Zeroizing::new(Vec::<u8>::new());
    if file
        .take(MAX_TOKEN_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return TokenFile::Unreadable;
    }
    if bytes.len() > MAX_TOKEN_FILE_BYTES {
        return TokenFile::Invalid;
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return TokenFile::Unreadable;
    };
    let text = text.trim();
    if text.is_empty() {
        TokenFile::Empty
    } else if !is_valid_token(text) {
        TokenFile::Invalid
    } else {
        TokenFile::Present(SecretString::from(text.to_owned()))
    }
}

/// Where a resolved token came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenSource {
    /// The service's `owner-token` file (a rotated or installer-written token).
    File,
    /// The pre-existing source; the file was missing or empty.
    Fallback,
    /// The pre-existing source; a token file exists but this account cannot
    /// read it, so a rotated token may be in use that the launcher cannot see.
    FallbackUnreadable,
}

/// Token-file first, then `fallback` (the launcher's existing source). A file
/// whose content is malformed is an error rather than a silent fallback: the
/// service would refuse to start with it, so signing in with the fallback
/// would only hide the real problem behind a 401.
pub fn resolve_owner_token(
    token_file: &Path,
    fallback: impl FnOnce() -> Result<SecretString>,
) -> Result<(SecretString, TokenSource)> {
    match read_token_file(token_file) {
        TokenFile::Present(token) => Ok((token, TokenSource::File)),
        TokenFile::Invalid => bail!(
            "The NeonHearth owner-token file is malformed (it must hold one token of at least 32 characters from A-Z a-z 0-9 . _ -). Rotate the token again from NeonHearth or delete the file {}.",
            token_file.display()
        ),
        TokenFile::Unreadable => fallback().map(|token| (token, TokenSource::FallbackUnreadable)),
        TokenFile::Missing | TokenFile::Empty => {
            fallback().map(|token| (token, TokenSource::Fallback))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::fs;

    const FAKE_FILE_TOKEN: &str = "fake-rotated-token-0123456789-ABCDEFGHIJ";
    const FAKE_FALLBACK: &str = "fake-installed-token-abcdefghijklmnop-0123";

    fn fallback() -> Result<SecretString> {
        Ok(SecretString::from(FAKE_FALLBACK))
    }
    fn unreachable_fallback() -> Result<SecretString> {
        panic!("the fallback must not be consulted");
    }
    fn resolve(path: &Path) -> (String, TokenSource) {
        let (token, source) = resolve_owner_token(path, fallback).unwrap();
        (token.expose_secret().to_owned(), source)
    }

    #[test]
    fn the_token_file_wins_over_the_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(OWNER_TOKEN_FILE);
        fs::write(&path, FAKE_FILE_TOKEN).unwrap();
        let (token, source) = resolve_owner_token(&path, unreachable_fallback).unwrap();
        assert_eq!(token.expose_secret(), FAKE_FILE_TOKEN);
        assert_eq!(source, TokenSource::File);
    }

    #[test]
    fn a_rotation_is_seen_on_the_next_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(OWNER_TOKEN_FILE);
        assert_eq!(
            resolve(&path),
            (FAKE_FALLBACK.to_owned(), TokenSource::Fallback)
        );
        fs::write(&path, FAKE_FILE_TOKEN).unwrap();
        assert_eq!(
            resolve(&path),
            (FAKE_FILE_TOKEN.to_owned(), TokenSource::File)
        );
        let rotated = "fake-second-rotation-zyxwvutsrqponm-9876";
        fs::write(&path, rotated).unwrap();
        assert_eq!(resolve(&path).0, rotated);
    }

    #[test]
    fn a_missing_file_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve(&dir.path().join("absent")),
            (FAKE_FALLBACK.to_owned(), TokenSource::Fallback)
        );
        assert!(matches!(
            read_token_file(&dir.path().join("absent")),
            TokenFile::Missing
        ));
    }

    #[test]
    fn an_empty_or_whitespace_file_falls_back_like_the_service() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(OWNER_TOKEN_FILE);
        for content in ["", "\n", "  \r\n\t "] {
            fs::write(&path, content).unwrap();
            assert_eq!(
                resolve(&path),
                (FAKE_FALLBACK.to_owned(), TokenSource::Fallback),
                "{content:?}"
            );
        }
    }

    #[test]
    fn surrounding_whitespace_and_a_trailing_newline_are_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(OWNER_TOKEN_FILE);
        for content in [
            format!("{FAKE_FILE_TOKEN}\n"),
            format!("{FAKE_FILE_TOKEN}\r\n"),
            format!("  {FAKE_FILE_TOKEN} \n\n"),
        ] {
            fs::write(&path, content).unwrap();
            assert_eq!(
                resolve(&path),
                (FAKE_FILE_TOKEN.to_owned(), TokenSource::File)
            );
        }
    }

    #[test]
    fn a_malformed_token_is_an_error_not_a_silent_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(OWNER_TOKEN_FILE);
        let bad = [
            // Forbidden characters (space inside, '=', '/', non-ASCII).
            "fake token with spaces 0123456789abcdefgh",
            "fake-padded-base64-token-0123456789abcdef==",
            "fake/slash/token/0123456789/abcdefghijklmnop",
            "fake-t\u{f6}ken-0123456789-abcdefghijklmnopqrs",
            // Too short.
            "fake-short-0123456789",
            // Long enough but fewer than 8 distinct bytes.
            "abababababababababababababababababababab",
            // Two lines is not one token.
            "fake-first-line-0123456789-abcdefghijkl\nfake-second-line-0123456789-abcdefghij",
        ];
        for content in bad {
            fs::write(&path, content).unwrap();
            assert!(
                matches!(read_token_file(&path), TokenFile::Invalid),
                "{content:?}"
            );
            let error = resolve_owner_token(&path, unreachable_fallback)
                .unwrap_err()
                .to_string();
            assert!(error.contains("malformed"));
            assert!(!error.contains(content), "the error must not echo the file");
        }
    }

    #[test]
    fn an_oversized_file_is_rejected_without_reading_it_all() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(OWNER_TOKEN_FILE);
        fs::write(&path, "a".repeat(MAX_TOKEN_FILE_BYTES + 1)).unwrap();
        assert!(matches!(read_token_file(&path), TokenFile::Invalid));
    }

    #[test]
    fn a_non_utf8_file_is_treated_like_an_unreadable_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(OWNER_TOKEN_FILE);
        fs::write(&path, [0xffu8, 0xfe, 0xfd, 0x80]).unwrap();
        assert_eq!(
            resolve(&path),
            (FAKE_FALLBACK.to_owned(), TokenSource::FallbackUnreadable)
        );
    }

    #[test]
    fn an_unreadable_path_falls_back_and_says_so() {
        // A directory where the file should be cannot be read as a token on
        // any platform, which is the portable stand-in for "access denied".
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(OWNER_TOKEN_FILE);
        fs::create_dir(&path).unwrap();
        assert_eq!(
            resolve(&path),
            (FAKE_FALLBACK.to_owned(), TokenSource::FallbackUnreadable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_file_denied_by_permissions_falls_back_and_says_so() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(OWNER_TOKEN_FILE);
        fs::write(&path, FAKE_FILE_TOKEN).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        if File::open(&path).is_ok() {
            // Running as root: permission bits do not apply.
            return;
        }
        assert_eq!(
            resolve(&path),
            (FAKE_FALLBACK.to_owned(), TokenSource::FallbackUnreadable)
        );
    }

    #[test]
    fn a_failing_fallback_is_reported_when_there_is_no_usable_file() {
        let dir = tempfile::tempdir().unwrap();
        let error = resolve_owner_token(&dir.path().join("absent"), || {
            bail!("no installed credential")
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("no installed credential"));
    }

    #[test]
    fn validation_matches_the_service_rule() {
        assert!(is_valid_token(FAKE_FILE_TOKEN));
        assert!(is_valid_token(&"Ab0._-xyz".repeat(4)));
        assert!(!is_valid_token(&"Ab0._-xyz".repeat(3))); // 27 < 32
        assert!(!is_valid_token(&"a1".repeat(20))); // 2 distinct
        assert!(!is_valid_token(&format!("{FAKE_FILE_TOKEN}!")));
        assert!(!is_valid_token(""));
    }

    #[test]
    fn the_portable_launcher_looks_where_the_service_it_starts_writes() {
        let path = portable_token_file(Path::new("state"));
        assert!(path.ends_with(Path::new("data").join("NeonHearth").join("owner-token")));
    }
}
