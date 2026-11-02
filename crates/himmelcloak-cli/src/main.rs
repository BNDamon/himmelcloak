use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    ConfigCheck,
    TestLogin,
    SyncUsers,
    ClearState,
}

fn parse_command(arguments: &[String]) -> Result<Command, &'static str> {
    match arguments {
        [config, check] if config == "config" && check == "check" => Ok(Command::ConfigCheck),
        [command] if command == "test-login" => Ok(Command::TestLogin),
        [command] if command == "sync-users" => Ok(Command::SyncUsers),
        [command] if command == "clear-state" => Ok(Command::ClearState),
        _ => Err("usage: himmelcloak-cli <config check|test-login|sync-users|clear-state>"),
    }
}

fn parse_config(contents: &str) -> Result<(), toml::de::Error> {
    toml::from_str::<toml::Value>(contents).map(|_| ())
}

fn check_config(path: &Path) -> Result<(), String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;

    parse_config(&contents).map_err(|error| format!("invalid {}: {error}", path.display()))
}

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();

    match parse_command(&arguments) {
        Ok(Command::ConfigCheck) => match check_config(Path::new("himmelcloak.toml")) {
            Ok(()) => {
                println!("himmelcloak-cli: himmelcloak.toml is valid");
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("himmelcloak-cli: {message}");
                ExitCode::FAILURE
            }
        },
        Ok(Command::TestLogin) => {
            println!("himmelcloak-cli: test-login is not implemented yet");
            ExitCode::SUCCESS
        }
        Ok(Command::SyncUsers) => {
            #[cfg(unix)]
            {
                match himmelcloak_cli::run_sync_users(Path::new("himmelcloak.toml")) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => {
                        eprintln!("himmelcloak-cli: sync-users: {error}");
                        ExitCode::FAILURE
                    }
                }
            }
            #[cfg(not(unix))]
            {
                eprintln!("himmelcloak-cli: sync-users requires Unix");
                ExitCode::FAILURE
            }
        }
        Ok(Command::ClearState) => {
            println!("himmelcloak-cli: clear-state is not implemented yet");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{check_config, parse_command, Command};

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_supported_commands() {
        assert_eq!(
            parse_command(&arguments(&["config", "check"])),
            Ok(Command::ConfigCheck)
        );
        assert_eq!(
            parse_command(&arguments(&["test-login"])),
            Ok(Command::TestLogin)
        );
        assert_eq!(
            parse_command(&arguments(&["sync-users"])),
            Ok(Command::SyncUsers)
        );
        assert_eq!(
            parse_command(&arguments(&["clear-state"])),
            Ok(Command::ClearState)
        );
    }

    #[test]
    fn rejects_unknown_commands() {
        assert!(parse_command(&arguments(&["unknown-command"])).is_err());
    }

    #[test]
    fn config_check_accepts_valid_toml_and_rejects_malformed_toml() {
        let path = std::env::temp_dir().join(format!(
            "himmelcloak-cli-config-test-{}.toml",
            std::process::id()
        ));

        fs::write(&path, "realm = \"himmelcloak-test\"\n").expect("write valid test config");
        assert!(check_config(&path).is_ok());

        fs::write(&path, "realm = [\n").expect("write malformed test config");
        assert!(check_config(&path).is_err());

        fs::remove_file(&path).expect("remove test config");
    }
}
