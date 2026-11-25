//! Copying a password to the clipboard and clearing it after a while.
//!
//! On Linux the process that copied the text has to keep serving it, so the
//! process stays resident until the clipboard is cleared, showing the
//! remaining time. Ctrl+C (or SIGTERM / SIGHUP) clears it early.

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use zeroize::Zeroizing;

/// How long the password stays in the clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(30);
/// How often the countdown checks for an interruption.
const TICK: Duration = Duration::from_millis(100);

/// The clipboard operations needed here, abstracted for tests.
pub trait Clipboard {
    fn set_text(&mut self, text: &str) -> Result<()>;
    /// Returns the current text, or `None` if the clipboard holds no text.
    fn get_text(&mut self) -> Option<Zeroizing<String>>;
    fn clear(&mut self) -> Result<()>;
}

impl Clipboard for arboard::Clipboard {
    fn set_text(&mut self, text: &str) -> Result<()> {
        arboard::Clipboard::set_text(self, text).context("failed to copy to the clipboard")
    }

    fn get_text(&mut self) -> Option<Zeroizing<String>> {
        arboard::Clipboard::get_text(self).ok().map(Zeroizing::new)
    }

    fn clear(&mut self) -> Result<()> {
        arboard::Clipboard::clear(self).context("failed to clear the clipboard")
    }
}

/// What happened to the clipboard at the end of [`hold`].
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The clipboard still held the password and was cleared.
    Cleared,
    /// Something else had been copied meanwhile, so it was left untouched.
    Replaced,
}

/// Copies `password` to the system clipboard and blocks until it is cleared,
/// either after [`CLEAR_AFTER`] or on Ctrl+C.
pub fn copy_and_hold(password: &str) -> Result<()> {
    // Install the handler before copying so that an interruption can never
    // leave the password behind.
    let interrupted = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&interrupted);
    ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst))
        .context("failed to install the Ctrl+C handler")?;

    let mut clipboard = arboard::Clipboard::new().context("failed to access the clipboard")?;
    Clipboard::set_text(&mut clipboard, password)?;
    hold(
        &mut clipboard,
        password,
        CLEAR_AFTER,
        &interrupted,
        &mut io::stderr(),
    )?;
    Ok(())
}

/// Waits until `timeout` elapses or `interrupted` is set, showing the
/// remaining seconds on `out`, then clears the clipboard if it still holds
/// `password`.
pub fn hold<C, W>(
    clipboard: &mut C,
    password: &str,
    timeout: Duration,
    interrupted: &AtomicBool,
    out: &mut W,
) -> Result<Outcome>
where
    C: Clipboard,
    W: Write,
{
    let deadline = Instant::now() + timeout;
    let mut shown = None;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || interrupted.load(Ordering::SeqCst) {
            break;
        }
        let secs = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
        if shown != Some(secs) {
            write!(
                out,
                "\rCopied the password to the clipboard. Clearing in {secs:>2}s (Ctrl+C to clear now)"
            )?;
            out.flush()?;
            shown = Some(secs);
        }
        std::thread::sleep(remaining.min(TICK));
    }
    if shown.is_some() {
        writeln!(out)?;
    }

    let still_ours = clipboard
        .get_text()
        .is_some_and(|current| current.as_str() == password);
    if still_ours {
        clipboard.clear()?;
        writeln!(out, "Cleared the clipboard.")?;
        Ok(Outcome::Cleared)
    } else {
        writeln!(
            out,
            "The clipboard content was changed by another application; left as is."
        )?;
        Ok(Outcome::Replaced)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// In-memory clipboard used by the tests.
    #[derive(Default)]
    pub(crate) struct FakeClipboard {
        pub(crate) text: Option<String>,
    }

    impl Clipboard for FakeClipboard {
        fn set_text(&mut self, text: &str) -> Result<()> {
            self.text = Some(text.to_owned());
            Ok(())
        }

        fn get_text(&mut self) -> Option<Zeroizing<String>> {
            self.text.clone().map(Zeroizing::new)
        }

        fn clear(&mut self) -> Result<()> {
            self.text = None;
            Ok(())
        }
    }

    fn copied(text: &str) -> FakeClipboard {
        FakeClipboard {
            text: Some(text.to_owned()),
        }
    }

    #[test]
    fn clears_after_timeout() {
        let mut clipboard = copied("pw");
        let mut out = Vec::new();
        let start = Instant::now();
        let outcome = hold(
            &mut clipboard,
            "pw",
            Duration::from_millis(150),
            &AtomicBool::new(false),
            &mut out,
        )
        .unwrap();
        assert!(start.elapsed() >= Duration::from_millis(150));
        assert_eq!(outcome, Outcome::Cleared);
        assert_eq!(clipboard.text, None);
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("Clearing in  1s"));
    }

    #[test]
    fn clears_immediately_when_interrupted() {
        let mut clipboard = copied("pw");
        let mut out = Vec::new();
        let start = Instant::now();
        let outcome = hold(
            &mut clipboard,
            "pw",
            Duration::from_secs(30),
            &AtomicBool::new(true),
            &mut out,
        )
        .unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(outcome, Outcome::Cleared);
        assert_eq!(clipboard.text, None);
    }

    #[test]
    fn leaves_clipboard_alone_when_replaced() {
        let mut clipboard = copied("something else");
        let mut out = Vec::new();
        let outcome = hold(
            &mut clipboard,
            "pw",
            Duration::ZERO,
            &AtomicBool::new(false),
            &mut out,
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Replaced);
        assert_eq!(clipboard.text.as_deref(), Some("something else"));
    }

    #[test]
    fn empty_clipboard_counts_as_replaced() {
        let mut clipboard = FakeClipboard::default();
        let mut out = Vec::new();
        let outcome = hold(
            &mut clipboard,
            "pw",
            Duration::ZERO,
            &AtomicBool::new(false),
            &mut out,
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Replaced);
    }
}
