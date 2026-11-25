//! `passmng add`: register a new entry with a generated password.

use anyhow::{Context, Result};
use inquire::validator::Validation;

use crate::clipboard;
use crate::password;
use crate::session::Session;
use crate::vault::{Entry, Vault};

pub fn run() -> Result<()> {
    let mut session = Session::open()?;

    let service = prompt_required("Service name:")?;
    let url = prompt_required("Service URL:")?;
    let id = {
        let vault = &session.vault;
        let service = service.as_str();
        inquire::Text::new("ID:")
            .with_validator(move |input: &str| Ok(validate_id(vault, service, input)))
            .prompt()?
    };
    let password = password::prompt_and_generate()?;
    let note = inquire::Text::new("Note (optional):").prompt()?;

    let entry = new_entry(service, url, id, password.to_string(), &note);
    let summary = format!("{} ({})", entry.service, entry.id);
    session.vault.add(entry)?;
    session.save()?;
    println!("Added {summary}.");

    clipboard::copy_and_hold(&password)
        .context("the entry was saved, but copying the password failed")
}

/// Asks for a value that must not be blank. The value is kept exactly as
/// typed.
fn prompt_required(message: &str) -> Result<String> {
    Ok(inquire::Text::new(message)
        .with_validator(|input: &str| Ok(validate_required(input)))
        .prompt()?)
}

fn validate_required(input: &str) -> Validation {
    if input.trim().is_empty() {
        Validation::Invalid("This field is required.".into())
    } else {
        Validation::Valid
    }
}

/// An ID is required and must not duplicate an existing (service, ID) pair.
fn validate_id(vault: &Vault, service: &str, id: &str) -> Validation {
    match validate_required(id) {
        Validation::Valid if vault.contains(service, id) => Validation::Invalid(
            format!("An entry for \"{service}\" with this ID already exists.").into(),
        ),
        other => other,
    }
}

/// Builds the entry from the prompted values; a blank note means no note.
fn new_entry(service: String, url: String, id: String, password: String, note: &str) -> Entry {
    Entry {
        service,
        url,
        id,
        password,
        note: (!note.trim().is_empty()).then(|| note.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_with(service: &str, id: &str) -> Vault {
        let mut vault = Vault::default();
        vault
            .add(new_entry(
                service.into(),
                "https://example.com".into(),
                id.into(),
                "pw".into(),
                "",
            ))
            .unwrap();
        vault
    }

    #[test]
    fn required_rejects_blank_input() {
        assert_eq!(validate_required("x"), Validation::Valid);
        assert!(matches!(validate_required(""), Validation::Invalid(_)));
        assert!(matches!(validate_required("  "), Validation::Invalid(_)));
    }

    #[test]
    fn id_rejects_duplicate_pair_case_insensitively() {
        let vault = vault_with("GitHub", "me");
        assert!(matches!(
            validate_id(&vault, "github", "ME"),
            Validation::Invalid(_)
        ));
        assert_eq!(validate_id(&vault, "github", "other"), Validation::Valid);
        assert_eq!(validate_id(&vault, "GitLab", "me"), Validation::Valid);
        assert!(matches!(
            validate_id(&vault, "GitLab", ""),
            Validation::Invalid(_)
        ));
    }

    #[test]
    fn new_entry_keeps_values_as_typed() {
        let entry = new_entry(
            " GitHub ".into(),
            "https://github.com".into(),
            "Me".into(),
            "pw".into(),
            " work ",
        );
        assert_eq!(entry.service, " GitHub ");
        assert_eq!(entry.id, "Me");
        assert_eq!(entry.note.as_deref(), Some(" work "));
    }

    #[test]
    fn blank_note_becomes_none() {
        let entry = new_entry("S".into(), "u".into(), "i".into(), "p".into(), "  ");
        assert_eq!(entry.note, None);
    }
}
