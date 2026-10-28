use clap::{Args, Parser, Subcommand};

/// A local-only password manager
#[derive(Debug, Parser)]
#[command(name = "passmng", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, PartialEq, Subcommand)]
enum Command {
    /// Set the vault directory and the master password
    Init,
    /// Add an entry
    Add,
    /// Remove an entry
    Rm(Target),
    /// List registered service names and their IDs
    List,
    /// Search entries by partial keyword match
    Search(SearchArgs),
    /// Show the ID and copy the password to the clipboard
    Show(Target),
    /// Edit an entry
    Edit(Target),
}

/// Selects the entry targeted by rm, show and edit
#[derive(Debug, PartialEq, Args)]
struct Target {
    /// Service name
    service: String,
    /// ID (skips selection when the service has several)
    #[arg(long)]
    id: Option<String>,
}

#[derive(Debug, PartialEq, Args)]
#[command(group = clap::ArgGroup::new("field").multiple(false))]
struct SearchArgs {
    /// Search keyword
    keyword: String,
    /// Search by service name (default)
    #[arg(long, group = "field")]
    name: bool,
    /// Search by URL
    #[arg(long, group = "field")]
    url: bool,
    /// Search by note
    #[arg(long, group = "field")]
    note: bool,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Init => println!("init: 未実装"),
        Command::Add => println!("add: 未実装"),
        Command::Rm(_) => println!("rm: 未実装"),
        Command::List => println!("list: 未実装"),
        Command::Search(_) => println!("search: 未実装"),
        Command::Show(_) => println!("show: 未実装"),
        Command::Edit(_) => println!("edit: 未実装"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Command, clap::Error> {
        Cli::try_parse_from(std::iter::once("passmng").chain(args.iter().copied()))
            .map(|cli| cli.command)
    }

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_subcommands_without_args() {
        assert_eq!(parse(&["init"]).unwrap(), Command::Init);
        assert_eq!(parse(&["add"]).unwrap(), Command::Add);
        assert_eq!(parse(&["list"]).unwrap(), Command::List);
    }

    #[test]
    fn parses_target_with_and_without_id() {
        assert_eq!(
            parse(&["rm", "GitHub"]).unwrap(),
            Command::Rm(Target { service: "GitHub".into(), id: None })
        );
        assert_eq!(
            parse(&["show", "GitHub", "--id", "me"]).unwrap(),
            Command::Show(Target { service: "GitHub".into(), id: Some("me".into()) })
        );
        assert_eq!(
            parse(&["edit", "GitHub", "--id", "me"]).unwrap(),
            Command::Edit(Target { service: "GitHub".into(), id: Some("me".into()) })
        );
    }

    #[test]
    fn target_requires_service() {
        assert!(parse(&["rm"]).is_err());
        assert!(parse(&["show"]).is_err());
        assert!(parse(&["edit"]).is_err());
    }

    #[test]
    fn parses_search_field_flags() {
        let Command::Search(args) = parse(&["search", "git"]).unwrap() else {
            panic!("search として解析されなかった");
        };
        assert_eq!(args.keyword, "git");
        assert!(!args.name && !args.url && !args.note);

        let Command::Search(args) = parse(&["search", "git", "--url"]).unwrap() else {
            panic!("search として解析されなかった");
        };
        assert!(args.url);
    }

    #[test]
    fn search_rejects_multiple_field_flags() {
        assert!(parse(&["search", "git", "--url", "--note"]).is_err());
        assert!(parse(&["search", "git", "--name", "--url"]).is_err());
    }

    #[test]
    fn search_requires_keyword() {
        assert!(parse(&["search"]).is_err());
        assert!(parse(&["search", "--url"]).is_err());
    }
}
