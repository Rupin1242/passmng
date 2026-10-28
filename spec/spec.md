# Local Password Manager

## Purpose

A password manager that runs entirely in the local environment.

## Functional Requirements

- Manage passwords for each service entirely within the local environment. No network communication is performed.
- One entry consists of a service name, service URL, ID, password, and note (optional).
- All entries are stored in a single vault file encrypted with the master password.
- The interface is a TUI. The user runs a subcommand (e.g. `passmng add`), and any required input is entered interactively.
- Target environments are Linux (X11 / Wayland) and WSL2 with WSLg enabled.

### Initialization

Running the initialization command determines the directory where the entries (the vault file) are stored.

The chosen directory is saved in the config file (`~/.config/passmng/config.toml`), and all subsequent commands refer to it.

During initialization, the user enters the master password twice to set it.

### Authentication

Every command except initialization asks for the master password and decrypts the vault. The input is not echoed.

### Add

Running the add command asks the user interactively for the service name, service URL, ID, password, and note.

Instead of entering the password directly, the user chooses the length and the character classes to use (uppercase letters, lowercase letters, digits, symbols).

- Generation uses the OS's cryptographically secure random number source.
- At least one character from each selected class is included.
- After saving, the generated password is copied to the clipboard.
- 30 seconds after copying, if the clipboard still contains the copied password, it is cleared automatically. Staying resident until it is cleared, displaying the remaining time, and clearing on interruption work the same as in the show command.

The pair of service name and ID is used as the unique identifier of an entry. Multiple entries with different IDs can be registered for the same service. Specifying a service name and ID pair that already exists is an error.

### Case Handling

- Service names and IDs are stored exactly as entered.
- Duplicate checks, entry selection, and partial matching in search are case-insensitive (e.g. `GitHub` and `github` are treated as the same).

### Entry Selection

Remove, show, and edit take a service name.

- If exactly one entry matches, it is the target.
- If several entries match, the user selects one interactively from the list of IDs.
- If an ID is given with the `--id` option, the selection is skipped and that entry is the target.

### Remove

Removes the selected entry. Confirmation is required before removal.

### List

Displays the registered service names, grouping the IDs under each service name.

### Search

Displays the service names and IDs of entries that partially match the keyword.

The search field is specified with the following options. Without an option, the service name is searched.

- `--name`: service name
- `--url`: URL
- `--note`: note

The options are flags given separately from the keyword (e.g. `passmng search github --url`). Specifying more than one option at the same time is an error.

### Show

Displays the ID of the selected entry and copies its password to the clipboard.

30 seconds after copying, if the clipboard still contains the copied password, it is cleared automatically.

- On Linux the copying process holds the clipboard content, so the process stays resident until the clipboard is cleared and displays the remaining time.
- If interrupted with Ctrl+C or similar, the clipboard is cleared before exiting.

### Edit

Edits the service name, service URL, ID, password, and note of the selected entry.

- As with the add command, data is edited interactively.
- Except for the password, the current value is displayed in gray.
- If the user presses Enter with an empty value, that field is left unchanged.
- For the password, the user is asked "Regenerate the password? (y/N)", and only on y are the length and character classes entered, as in the add command, to regenerate it.
- If only `-` is entered for the note, the note is deleted.
- If the edited service name and ID pair duplicates another existing entry, it is an error and the changes are not saved.

## Subcommands

The subcommand for each feature is as follows.

|Feature|Command|Options|
|:--|:--|:--|
|Initialize|passmng init||
|Add|passmng add||
|Remove|passmng rm <service>|--id <ID>|
|List|passmng list||
|Search|passmng search <keyword>|--name \| --url \| --note|
|Show|passmng show <service>|--id <ID>|
|Edit|passmng edit <service>|--id <ID>|

## Security

- A key is derived from the master password with Argon2id, and the entire vault is encrypted with XChaCha20-Poly1305.
- The vault is a single file so that service names do not leak through file names or similar.
- Plaintext passwords and keys are erased from memory (zeroized) after use.
- The vault is written to a temporary file and then renamed, to prevent corruption from an interrupted write.

## Abnormal Termination

If the master password is entered incorrectly three times in a row, the program exits with an error.

## Future Work

- Changing the master password
- Not requiring the master password again for a period of time once it has been entered
- The clipboard clearing time is fixed at 30 seconds; making it configurable

## Tech Stack

Rust only, in principle.

Main crates expected: `clap`, `inquire`, `rpassword`, `serde`, `argon2`, `chacha20poly1305`, `rand`, `zeroize`, `arboard`, `dirs`

## Testing

Use Rust's built-in test framework and write test code for each feature as it is implemented.

## Comments

All comments in the source code must be in English.
