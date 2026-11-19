//! `passmng init`: choose the vault directory and set the master password.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::config::{self, Config, VAULT_FILE_NAME};
use crate::fsutil;
use crate::vault::{KdfParams, Vault};

/// How many times the user may enter a non-matching or empty master password
/// before init gives up.
const MAX_PASSWORD_ATTEMPTS: usize = 3;

pub fn run() -> Result<()> {
    let config_path = config::default_path()?;
    ensure_no_config(&config_path)?;

    let default_dir = config::default_vault_dir()?;
    let input = inquire::Text::new("Vault directory:")
        .with_default(&default_dir.display().to_string())
        .prompt()?;
    let vault_dir = resolve_dir(&input, dirs::home_dir().as_deref())?;
    // Check before asking for the password so that the user does not type it
    // for nothing.
    ensure_no_vault(&vault_dir)?;

    let password = read_new_password(
        |prompt| rpassword::prompt_password(prompt).map(Zeroizing::new),
        &mut io::stderr(),
    )?;

    initialize(
        &config_path,
        &vault_dir,
        password.as_bytes(),
        KdfParams::DEFAULT,
    )?;
    println!(
        "Initialized the vault at {}",
        vault_dir.join(VAULT_FILE_NAME).display()
    );
    Ok(())
}

/// Creates an empty vault in `vault_dir` and writes the config pointing to it.
///
/// The vault is written before the config, so a failure never leaves a config
/// that points to a missing vault.
fn initialize(
    config_path: &Path,
    vault_dir: &Path,
    password: &[u8],
    params: KdfParams,
) -> Result<()> {
    ensure_no_config(config_path)?;
    ensure_no_vault(vault_dir)?;

    fsutil::create_private_dir_all(vault_dir)?;
    let config = Config {
        vault_dir: vault_dir.to_path_buf(),
    };
    Vault::default().save(&config.vault_path(), password, params)?;
    config.save(config_path)
}

fn ensure_no_config(config_path: &Path) -> Result<()> {
    if config_path.exists() {
        bail!(
            "already initialized (config file exists: {})",
            config_path.display()
        );
    }
    Ok(())
}

fn ensure_no_vault(vault_dir: &Path) -> Result<()> {
    let vault_path = vault_dir.join(VAULT_FILE_NAME);
    if vault_path.exists() {
        bail!("a vault already exists at {}", vault_path.display());
    }
    Ok(())
}

/// Turns the directory typed by the user into an absolute path, expanding a
/// leading `~`.
fn resolve_dir(input: &str, home: Option<&Path>) -> Result<PathBuf> {
    let input = input.trim();
    if input.is_empty() {
        bail!("the vault directory must not be empty");
    }
    let path = if input == "~" || input.starts_with("~/") {
        let home = home.context("cannot determine the home directory")?;
        home.join(input.trim_start_matches('~').trim_start_matches('/'))
    } else {
        PathBuf::from(input)
    };
    std::path::absolute(&path).with_context(|| format!("invalid path: {}", path.display()))
}

/// Asks for the new master password twice until both inputs match and are
/// non-empty, giving up after [`MAX_PASSWORD_ATTEMPTS`] failures.
///
/// `read` prompts for one password without echo; `out` receives the messages
/// explaining why an attempt was rejected.
fn read_new_password<R, W>(mut read: R, out: &mut W) -> Result<Zeroizing<String>>
where
    R: FnMut(&str) -> io::Result<Zeroizing<String>>,
    W: Write,
{
    for _ in 0..MAX_PASSWORD_ATTEMPTS {
        let first = read("Master password: ").context("failed to read the password")?;
        if first.is_empty() {
            writeln!(out, "The master password must not be empty.")?;
            continue;
        }
        let second = read("Confirm master password: ").context("failed to read the password")?;
        if *first == *second {
            return Ok(first);
        }
        writeln!(out, "Passwords do not match.")?;
    }
    bail!("failed to set the master password {MAX_PASSWORD_ATTEMPTS} times in a row")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::tests::TEST_PARAMS;

    /// Returns a `read` callback that yields `inputs` in order.
    fn inputs(inputs: &[&str]) -> impl FnMut(&str) -> io::Result<Zeroizing<String>> {
        let mut iter = inputs
            .iter()
            .map(|s| Zeroizing::new(s.to_string()))
            .collect::<Vec<_>>()
            .into_iter();
        move |_| Ok(iter.next().expect("no more inputs"))
    }

    #[test]
    fn password_accepted_when_both_inputs_match() {
        let mut out = Vec::new();
        let password = read_new_password(inputs(&["pw", "pw"]), &mut out).unwrap();
        assert_eq!(password.as_str(), "pw");
        assert!(out.is_empty());
    }

    #[test]
    fn password_retried_after_mismatch_or_empty_input() {
        let mut out = Vec::new();
        let password = read_new_password(inputs(&["a", "b", "", "pw", "pw"]), &mut out).unwrap();
        assert_eq!(password.as_str(), "pw");
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("do not match"));
        assert!(out.contains("must not be empty"));
    }

    #[test]
    fn password_fails_after_three_failures() {
        let mut out = Vec::new();
        let result = read_new_password(inputs(&["a", "b", "c", "d", "e", "f"]), &mut out);
        assert!(result.is_err());
    }

    #[test]
    fn password_read_error_is_propagated() {
        let mut out = Vec::new();
        let result = read_new_password(
            |_| Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof")),
            &mut out,
        );
        assert!(result.is_err());
    }

    #[test]
    fn resolve_dir_expands_tilde() {
        let home = Path::new("/home/user");
        assert_eq!(
            resolve_dir("~/vault", Some(home)).unwrap(),
            PathBuf::from("/home/user/vault")
        );
        assert_eq!(
            resolve_dir("~", Some(home)).unwrap(),
            PathBuf::from("/home/user")
        );
    }

    #[test]
    fn resolve_dir_keeps_absolute_and_absolutizes_relative() {
        assert_eq!(
            resolve_dir(" /srv/vault ", None).unwrap(),
            PathBuf::from("/srv/vault")
        );
        let resolved = resolve_dir("vault", None).unwrap();
        assert!(resolved.is_absolute());
        assert!(resolved.ends_with("vault"));
    }

    #[test]
    fn resolve_dir_rejects_empty_input() {
        assert!(resolve_dir("  ", None).is_err());
    }

    #[test]
    fn initialize_creates_vault_and_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config").join("config.toml");
        let vault_dir = tmp.path().join("data").join("passmng");

        initialize(&config_path, &vault_dir, b"master", TEST_PARAMS).unwrap();

        let config = Config::load(&config_path).unwrap();
        assert_eq!(config.vault_dir, vault_dir);
        let data = std::fs::read(config.vault_path()).unwrap();
        assert!(Vault::decrypt(&data, b"master").unwrap().entries.is_empty());
    }

    #[test]
    fn initialize_fails_when_config_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        std::fs::write(&config_path, "").unwrap();
        let vault_dir = tmp.path().join("vault");

        assert!(initialize(&config_path, &vault_dir, b"master", TEST_PARAMS).is_err());
        assert!(!vault_dir.exists());
    }

    #[test]
    fn initialize_does_not_overwrite_existing_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.toml");
        let vault_dir = tmp.path().join("vault");
        std::fs::create_dir(&vault_dir).unwrap();
        let vault_path = vault_dir.join(VAULT_FILE_NAME);
        std::fs::write(&vault_path, b"existing").unwrap();

        assert!(initialize(&config_path, &vault_dir, b"master", TEST_PARAMS).is_err());
        assert_eq!(std::fs::read(&vault_path).unwrap(), b"existing");
        assert!(!config_path.exists());
    }
}
