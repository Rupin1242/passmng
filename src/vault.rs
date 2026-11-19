//! The encrypted vault file.
//!
//! File layout (all integers little-endian):
//!
//! | Offset | Size | Field                          |
//! |-------:|-----:|:-------------------------------|
//! |      0 |    4 | magic `PMNG`                   |
//! |      4 |    1 | format version (1)             |
//! |      5 |    4 | Argon2id memory cost (KiB)     |
//! |      9 |    4 | Argon2id time cost             |
//! |     13 |    4 | Argon2id parallelism           |
//! |     17 |   16 | salt                           |
//! |     33 |   24 | XChaCha20-Poly1305 nonce       |
//! |     57 |    - | ciphertext + 16-byte tag       |
//!
//! The whole header is passed as associated data, so tampering with the KDF
//! parameters, salt or nonce makes decryption fail. The plaintext is the TOML
//! serialization of [`Vault`]. A fresh salt and nonce are generated on every
//! save.

use std::fmt;
use std::path::Path;

use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::TryRng;
use rand::rngs::SysRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::fsutil;

const MAGIC: &[u8; 4] = b"PMNG";
const FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 4 + 1 + 4 * 3 + SALT_LEN + NONCE_LEN;

/// One password entry.
///
/// Every field is zeroized when the entry is dropped. `Debug` is
/// intentionally not derived so that passwords cannot end up in logs.
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub service: String,
    pub url: String,
    pub id: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The decrypted contents of the vault file.
#[derive(Default, PartialEq, Serialize, Deserialize)]
pub struct Vault {
    #[serde(default)]
    pub entries: Vec<Entry>,
}

/// Argon2id cost parameters, stored in the vault header so that they can be
/// raised in the future without breaking existing vaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// RFC 9106 second recommended option: 64 MiB, 3 passes, 4 lanes.
    pub const DEFAULT: Self = Self {
        m_cost: 64 * 1024,
        t_cost: 3,
        p_cost: 4,
    };
}

/// Why a vault could not be opened.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used by the commands after init")
)]
#[derive(Debug, PartialEq, Eq)]
pub enum DecryptError {
    /// The file is not a vault or is truncated / of an unknown version.
    Format(String),
    /// Authentication failed: the master password is wrong or the file was
    /// modified.
    WrongPassword,
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(reason) => write!(f, "invalid vault file: {reason}"),
            Self::WrongPassword => f.write_str("wrong master password or corrupted vault"),
        }
    }
}

impl std::error::Error for DecryptError {}

impl Vault {
    /// Encrypts the vault with `password` and writes it to `path` atomically.
    pub fn save(&self, path: &Path, password: &[u8], params: KdfParams) -> Result<()> {
        let data = self.encrypt(password, params)?;
        fsutil::write_atomic(path, &data)
    }

    /// Encrypts the vault into the on-disk format.
    pub fn encrypt(&self, password: &[u8], params: KdfParams) -> Result<Vec<u8>> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        let mut rng = SysRng;
        rng.try_fill_bytes(&mut salt)
            .and_then(|()| rng.try_fill_bytes(&mut nonce))
            .context("failed to get random bytes from the OS")?;

        let mut data = Vec::with_capacity(HEADER_LEN);
        data.extend_from_slice(MAGIC);
        data.push(FORMAT_VERSION);
        data.extend_from_slice(&params.m_cost.to_le_bytes());
        data.extend_from_slice(&params.t_cost.to_le_bytes());
        data.extend_from_slice(&params.p_cost.to_le_bytes());
        data.extend_from_slice(&salt);
        data.extend_from_slice(&nonce);
        debug_assert_eq!(data.len(), HEADER_LEN);

        let plaintext =
            Zeroizing::new(toml::to_string(self).context("failed to serialize the vault")?);
        let key = derive_key(password, &salt, params)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| anyhow::anyhow!("invalid key length"))?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                chacha20poly1305::aead::Payload {
                    msg: plaintext.as_bytes(),
                    aad: &data,
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to encrypt the vault"))?;
        data.extend_from_slice(&ciphertext);
        Ok(data)
    }

    /// Decrypts data produced by [`Vault::encrypt`].
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the commands after init")
    )]
    pub fn decrypt(data: &[u8], password: &[u8]) -> Result<Self, DecryptError> {
        let format = |reason: &str| DecryptError::Format(reason.to_owned());

        if data.len() < HEADER_LEN || &data[..4] != MAGIC {
            return Err(format("not a passmng vault"));
        }
        if data[4] != FORMAT_VERSION {
            return Err(format("unsupported format version"));
        }
        let read_u32 = |offset: usize| {
            u32::from_le_bytes(data[offset..offset + 4].try_into().expect("4-byte slice"))
        };
        let params = KdfParams {
            m_cost: read_u32(5),
            t_cost: read_u32(9),
            p_cost: read_u32(13),
        };
        let salt = &data[17..17 + SALT_LEN];
        let nonce: [u8; NONCE_LEN] = data[33..HEADER_LEN].try_into().expect("nonce slice");
        let (header, ciphertext) = data.split_at(HEADER_LEN);

        let key = derive_key(password, salt, params).map_err(|e| format(&format!("{e:#}")))?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| format("invalid key length"))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(nonce),
                    chacha20poly1305::aead::Payload {
                        msg: ciphertext,
                        aad: header,
                    },
                )
                .map_err(|_| DecryptError::WrongPassword)?,
        );
        let text = std::str::from_utf8(&plaintext).map_err(|_| format("payload is not UTF-8"))?;
        toml::from_str(text).map_err(|_| format("payload is malformed"))
    }
}

/// Derives the encryption key from the master password with Argon2id.
fn derive_key(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| anyhow::anyhow!("invalid Argon2 parameters: {e}"))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, key.as_mut_slice())
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Cheap parameters so that tests run fast.
    pub(crate) const TEST_PARAMS: KdfParams = KdfParams {
        m_cost: 64,
        t_cost: 1,
        p_cost: 1,
    };

    fn sample_vault() -> Vault {
        Vault {
            entries: vec![
                Entry {
                    service: "GitHub".into(),
                    url: "https://github.com".into(),
                    id: "me".into(),
                    password: "s3cret!".into(),
                    note: Some("work account".into()),
                },
                Entry {
                    service: "Example".into(),
                    url: "https://example.com".into(),
                    id: "other".into(),
                    password: "p@ss".into(),
                    note: None,
                },
            ],
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let vault = sample_vault();
        let data = vault.encrypt(b"master", TEST_PARAMS).unwrap();
        assert!(Vault::decrypt(&data, b"master").unwrap() == vault);
    }

    #[test]
    fn empty_vault_round_trip() {
        let data = Vault::default().encrypt(b"master", TEST_PARAMS).unwrap();
        assert!(Vault::decrypt(&data, b"master").unwrap().entries.is_empty());
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let data = sample_vault().encrypt(b"master", TEST_PARAMS).unwrap();
        let contains = |needle: &[u8]| data.windows(needle.len()).any(|w| w == needle);
        assert!(!contains(b"GitHub"));
        assert!(!contains(b"s3cret!"));
    }

    #[test]
    fn each_save_uses_fresh_salt_and_nonce() {
        let vault = sample_vault();
        let a = vault.encrypt(b"master", TEST_PARAMS).unwrap();
        let b = vault.encrypt(b"master", TEST_PARAMS).unwrap();
        assert_ne!(a[17..HEADER_LEN], b[17..HEADER_LEN]);
    }

    #[test]
    fn header_stores_kdf_params() {
        let data = Vault::default().encrypt(b"master", TEST_PARAMS).unwrap();
        assert_eq!(&data[..4], MAGIC);
        assert_eq!(data[4], FORMAT_VERSION);
        assert_eq!(data[5..9], 64u32.to_le_bytes());
        assert_eq!(data[9..13], 1u32.to_le_bytes());
        assert_eq!(data[13..17], 1u32.to_le_bytes());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let data = sample_vault().encrypt(b"master", TEST_PARAMS).unwrap();
        assert_eq!(
            Vault::decrypt(&data, b"wrong").err(),
            Some(DecryptError::WrongPassword)
        );
    }

    #[test]
    fn tampered_header_or_ciphertext_is_rejected() {
        let data = sample_vault().encrypt(b"master", TEST_PARAMS).unwrap();
        // Flip a salt byte (header, authenticated as AAD).
        let mut tampered = data.clone();
        tampered[20] ^= 1;
        assert_eq!(
            Vault::decrypt(&tampered, b"master").err(),
            Some(DecryptError::WrongPassword)
        );
        // Flip the last ciphertext/tag byte.
        let mut tampered = data;
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            Vault::decrypt(&tampered, b"master").err(),
            Some(DecryptError::WrongPassword)
        );
    }

    #[test]
    fn non_vault_data_is_a_format_error() {
        assert!(matches!(
            Vault::decrypt(b"hello", b"master"),
            Err(DecryptError::Format(_))
        ));
        let mut data = Vault::default().encrypt(b"master", TEST_PARAMS).unwrap();
        data[4] = 99;
        assert!(matches!(
            Vault::decrypt(&data, b"master"),
            Err(DecryptError::Format(_))
        ));
    }

    #[test]
    fn save_writes_decryptable_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        let vault = sample_vault();
        vault.save(&path, b"master", TEST_PARAMS).unwrap();
        let data = std::fs::read(&path).unwrap();
        assert!(Vault::decrypt(&data, b"master").unwrap() == vault);
    }
}
