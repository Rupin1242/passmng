//! Authentication: asks for the master password and opens the vault.
//!
//! Every command except `init` starts by calling [`Session::open`].

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::config::{self, Config};
use crate::vault::{DecryptError, KdfParams, Vault};

/// How many wrong master passwords in a row are tolerated before exiting.
const MAX_PASSWORD_ATTEMPTS: usize = 3;

/// An unlocked vault together with what is needed to save it again.
pub struct Session {
    pub vault: Vault,
    path: PathBuf,
    password: Zeroizing<String>,
    params: KdfParams,
}

impl Session {
    /// Loads the config, then asks for the master password until the vault
    /// decrypts.
    pub fn open() -> Result<Self> {
        let config_path = config::default_path()?;
        if !config_path.exists() {
            bail!("not initialized yet; run `passmng init` first");
        }
        let config = Config::load(&config_path)?;
        Self::unlock(
            &config.vault_path(),
            |prompt| rpassword::prompt_password(prompt).map(Zeroizing::new),
            &mut io::stderr(),
        )
    }

    /// Reads the vault at `path` and decrypts it with a password obtained from
    /// `read`, retrying up to [`MAX_PASSWORD_ATTEMPTS`] times.
    fn unlock<R, W>(path: &Path, mut read: R, out: &mut W) -> Result<Self>
    where
        R: FnMut(&str) -> io::Result<Zeroizing<String>>,
        W: Write,
    {
        let data =
            std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        for _ in 0..MAX_PASSWORD_ATTEMPTS {
            let password = read("Master password: ").context("failed to read the password")?;
            match Vault::decrypt(&data, password.as_bytes()) {
                Ok((vault, params)) => {
                    return Ok(Self {
                        vault,
                        path: path.to_path_buf(),
                        password,
                        params,
                    });
                }
                Err(DecryptError::WrongPassword) => {
                    writeln!(out, "Wrong master password.")?;
                }
                Err(e @ DecryptError::Format(_)) => return Err(e.into()),
            }
        }
        bail!("wrong master password {MAX_PASSWORD_ATTEMPTS} times in a row")
    }

    /// Encrypts the vault with the same master password and KDF parameters
    /// and writes it back atomically.
    pub fn save(&self) -> Result<()> {
        self.vault
            .save(&self.path, self.password.as_bytes(), self.params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::tests::TEST_PARAMS;

    fn inputs(inputs: &[&str]) -> impl FnMut(&str) -> io::Result<Zeroizing<String>> {
        let mut iter = inputs
            .iter()
            .map(|s| Zeroizing::new(s.to_string()))
            .collect::<Vec<_>>()
            .into_iter();
        move |_| Ok(iter.next().expect("no more inputs"))
    }

    fn vault_file() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        Vault::default()
            .save(&path, b"master", TEST_PARAMS)
            .unwrap();
        (dir, path)
    }

    #[test]
    fn unlock_succeeds_after_retries() {
        let (_dir, path) = vault_file();
        let mut out = Vec::new();
        let session = Session::unlock(&path, inputs(&["x", "y", "master"]), &mut out).unwrap();
        assert!(session.vault.entries.is_empty());
        assert_eq!(session.params, TEST_PARAMS);
        let out = String::from_utf8(out).unwrap();
        assert_eq!(out.matches("Wrong master password.").count(), 2);
    }

    #[test]
    fn unlock_fails_after_three_wrong_passwords() {
        let (_dir, path) = vault_file();
        let mut out = Vec::new();
        let result = Session::unlock(&path, inputs(&["a", "b", "c", "master"]), &mut out);
        assert!(result.is_err());
    }

    #[test]
    fn unlock_fails_immediately_on_invalid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        std::fs::write(&path, b"garbage").unwrap();
        let mut out = Vec::new();
        // Only one input is available, so a retry would panic.
        let result = Session::unlock(&path, inputs(&["master"]), &mut out);
        assert!(result.is_err());
    }

    #[test]
    fn save_keeps_password_and_params() {
        let (_dir, path) = vault_file();
        let mut out = Vec::new();
        let mut session = Session::unlock(&path, inputs(&["master"]), &mut out).unwrap();
        session.vault.entries.push(crate::vault::Entry {
            service: "S".into(),
            url: "u".into(),
            id: "i".into(),
            password: "p".into(),
            note: None,
        });
        session.save().unwrap();

        let data = std::fs::read(&path).unwrap();
        let (vault, params) = Vault::decrypt(&data, b"master").unwrap();
        assert_eq!(vault.entries.len(), 1);
        assert_eq!(params, TEST_PARAMS);
    }
}
