//! Password generation and the prompts that configure it.

use std::fmt;

use anyhow::{Result, bail};
use rand::seq::{IndexedRandom, SliceRandom};
use rand::{CryptoRng, rand_core::UnwrapErr, rngs::SysRng};
use zeroize::Zeroizing;

/// Default password length offered by the prompt.
pub const DEFAULT_LENGTH: usize = 20;
/// Upper bound on the password length accepted by the prompt.
pub const MAX_LENGTH: usize = 128;

/// A class of characters a generated password may contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharClass {
    Upper,
    Lower,
    Digit,
    Symbol,
}

impl CharClass {
    pub const ALL: [Self; 4] = [Self::Upper, Self::Lower, Self::Digit, Self::Symbol];

    /// The characters belonging to this class (all printable ASCII).
    pub fn chars(self) -> &'static [u8] {
        match self {
            Self::Upper => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            Self::Lower => b"abcdefghijklmnopqrstuvwxyz",
            Self::Digit => b"0123456789",
            Self::Symbol => b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
        }
    }
}

impl fmt::Display for CharClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Upper => "Uppercase letters (A-Z)",
            Self::Lower => "Lowercase letters (a-z)",
            Self::Digit => "Digits (0-9)",
            Self::Symbol => "Symbols (!\"#$%...)",
        })
    }
}

/// Generates a password of `length` characters drawn from `classes`,
/// containing at least one character of every selected class.
pub fn generate<R: CryptoRng>(
    length: usize,
    classes: &[CharClass],
    rng: &mut R,
) -> Result<Zeroizing<String>> {
    if classes.is_empty() {
        bail!("select at least one character class");
    }
    if length < classes.len() {
        bail!(
            "the length must be at least {} to include every selected class",
            classes.len()
        );
    }

    let pool: Vec<u8> = classes.iter().flat_map(|c| c.chars()).copied().collect();
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    // One guaranteed character per class, then fill from the whole pool and
    // shuffle so that the guaranteed characters are not at fixed positions.
    for class in classes {
        bytes.push(*class.chars().choose(rng).expect("class is not empty"));
    }
    while bytes.len() < length {
        bytes.push(*pool.choose(rng).expect("pool is not empty"));
    }
    bytes.shuffle(rng);

    let text = String::from_utf8(std::mem::take(&mut *bytes)).expect("ASCII only");
    Ok(Zeroizing::new(text))
}

/// Asks for the character classes and the length, then generates a password
/// with the OS's cryptographically secure random number source.
pub fn prompt_and_generate() -> Result<Zeroizing<String>> {
    let classes = inquire::MultiSelect::new("Character classes:", CharClass::ALL.to_vec())
        .with_default(&[0, 1, 2, 3])
        .with_validator(
            |selected: &[inquire::list_option::ListOption<&CharClass>]| {
                Ok(if selected.is_empty() {
                    inquire::validator::Validation::Invalid("Select at least one class.".into())
                } else {
                    inquire::validator::Validation::Valid
                })
            },
        )
        .prompt()?;

    let min = classes.len();
    let length = inquire::CustomType::<usize>::new("Password length:")
        .with_default(DEFAULT_LENGTH.max(min))
        .with_error_message("Enter a number.")
        .with_validator(move |&n: &usize| {
            Ok(if (min..=MAX_LENGTH).contains(&n) {
                inquire::validator::Validation::Valid
            } else {
                inquire::validator::Validation::Invalid(
                    format!("Enter a number between {min} and {MAX_LENGTH}.").into(),
                )
            })
        })
        .prompt()?;

    generate(length, &classes, &mut UnwrapErr(SysRng))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> UnwrapErr<SysRng> {
        UnwrapErr(SysRng)
    }

    fn count_in(password: &str, class: CharClass) -> usize {
        password
            .bytes()
            .filter(|b| class.chars().contains(b))
            .count()
    }

    #[test]
    fn generates_requested_length() {
        for length in [4, 20, MAX_LENGTH] {
            let pw = generate(length, &CharClass::ALL, &mut rng()).unwrap();
            assert_eq!(pw.len(), length);
        }
    }

    #[test]
    fn includes_every_selected_class() {
        // With length == number of classes, each class appears exactly once.
        for _ in 0..50 {
            let pw = generate(4, &CharClass::ALL, &mut rng()).unwrap();
            for class in CharClass::ALL {
                assert_eq!(
                    count_in(&pw, class),
                    1,
                    "{class} missing in generated password"
                );
            }
        }
    }

    #[test]
    fn uses_only_selected_classes() {
        let classes = [CharClass::Lower, CharClass::Digit];
        let pw = generate(64, &classes, &mut rng()).unwrap();
        assert_eq!(count_in(&pw, CharClass::Upper), 0);
        assert_eq!(count_in(&pw, CharClass::Symbol), 0);
        assert!(count_in(&pw, CharClass::Lower) >= 1);
        assert!(count_in(&pw, CharClass::Digit) >= 1);
    }

    #[test]
    fn rejects_no_classes_or_too_short_length() {
        assert!(generate(10, &[], &mut rng()).is_err());
        assert!(generate(3, &CharClass::ALL, &mut rng()).is_err());
        assert!(generate(0, &[CharClass::Digit], &mut rng()).is_err());
    }

    #[test]
    fn character_classes_are_disjoint_printable_ascii() {
        let mut all: Vec<u8> = CharClass::ALL
            .iter()
            .flat_map(|c| c.chars())
            .copied()
            .collect();
        assert!(all.iter().all(|b| b.is_ascii_graphic()));
        let len = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), len);
        // Every printable ASCII character except space is covered.
        assert_eq!(len, 94);
    }

    #[test]
    fn consecutive_passwords_differ() {
        let a = generate(32, &CharClass::ALL, &mut rng()).unwrap();
        let b = generate(32, &CharClass::ALL, &mut rng()).unwrap();
        assert_ne!(*a, *b);
    }
}
