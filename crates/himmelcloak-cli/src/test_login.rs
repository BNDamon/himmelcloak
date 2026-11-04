use himmelcloak::config::Config;
use himmelcloak::{Answer, AuthStep, Challenge, PublicClientApplication, Start};
use serde::Deserialize;
use std::io::{self, Write};
use std::{fs, path::Path, path::PathBuf};
use zeroize::Zeroizing;

type LoginResult<T> = Result<T, &'static str>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginSettings {
    server_url: String,
    realm: String,
    client_id: String,
    ca_bundle: Option<PathBuf>,
}

fn load_config(path: &Path) -> LoginResult<Config> {
    let source = Zeroizing::new(fs::read_to_string(path).map_err(|_| "cannot read configuration")?);
    parse_login_config(&source)
}

fn parse_login_config(source: &str) -> LoginResult<Config> {
    let document: toml::Value = toml::from_str(source).map_err(|_| "malformed configuration")?;
    let settings: LoginSettings = document
        .get("login")
        .ok_or("missing [login] settings")?
        .clone()
        .try_into()
        .map_err(|_| "invalid [login] settings")?;

    let mut config = Config::new(&settings.server_url, &settings.realm, &settings.client_id)
        .map_err(|_| "invalid login configuration")?;
    config.ca_bundle = settings.ca_bundle;
    Ok(config)
}
struct RestoreEcho(libc::termios);

impl Drop for RestoreEcho {
    fn drop(&mut self) {
        // SAFETY: these settings were read from the same terminal descriptor.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0);
        }
    }
}

fn read_input(prompt: &str, hidden: bool) -> LoginResult<Zeroizing<String>> {
    print!("{prompt}");
    io::stdout().flush().map_err(|_| "cannot write prompt")?;

    let restore = if hidden {
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();

        // SAFETY: original points to writable storage for terminal settings.
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, original.as_mut_ptr()) } != 0 {
            return Err("password input requires an interactive terminal");
        }

        // SAFETY: tcgetattr initialized the settings on success.
        let original = unsafe { original.assume_init() };
        let mut settings = original;
        settings.c_lflag &= !libc::ECHO;

        // SAFETY: settings contains initialized terminal settings.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &settings) } != 0 {
            return Err("cannot hide password input");
        }

        Some(RestoreEcho(original))
    } else {
        None
    };

    let mut value = Zeroizing::new(String::new());
    let result = io::stdin().read_line(&mut value);

    drop(restore);
    if hidden {
        println!();
    }

    let count = result.map_err(|_| "cannot read input")?;
    if count == 0 {
        return Err("input ended before login completed");
    }

    let length = value.trim_end_matches(['\r', '\n']).len();
    value.truncate(length);

    if value.is_empty() {
        return Err("input must not be empty");
    }

    Ok(value)
}
async fn login(config: Config) -> LoginResult<()> {
    let client = PublicClientApplication::with_config(config)
        .await
        .map_err(|_| "cannot connect to Keycloak")?;

    let (mut flow, mut step) = client
        .initiate_auth_flow(Start::default())
        .await
        .map_err(|_| "cannot start login")?;

    loop {
        let answer = match step {
            AuthStep::Complete(_) => return Ok(()),
            AuthStep::Failed { .. } => return Err("login failed"),
            AuthStep::Challenge(Challenge::Username) => {
                let mut username = read_input("Username: ", false)?;
                Answer::Username(std::mem::take(&mut *username))
            }
            AuthStep::Challenge(Challenge::Password) => {
                let mut password = read_input("Password: ", true)?;
                Answer::Password(std::mem::take(&mut *password))
            }
            _ => {
                flow.cancel();
                return Err("this command currently supports password login only");
            }
        };

        step = client
            .continue_auth_flow(&mut flow, answer)
            .await
            .map_err(|_| "login failed")?;
    }
}

pub fn run(path: &Path) -> LoginResult<()> {
    let config = load_config(path)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "cannot start login runtime")?;

    runtime.block_on(login(config))
}
#[cfg(test)]
mod tests {
    use super::parse_login_config;
    use std::path::PathBuf;

    const VALID: &str = r#"
[login]
server_url = "https://keycloak.test:8443"
realm = "himmelcloak-test"
client_id = "himmelcloak-test-client"
ca_bundle = "/work/tests/keycloak/.generated/ca.pem"
"#;

    #[test]
    fn reads_login_settings_and_preserves_unrelated_tables() {
        let source = format!("{VALID}\n[sync]\nallowed_group_id = 'example'\n");
        let config = parse_login_config(&source).unwrap();

        assert_eq!(config.server_url.as_str(), "https://keycloak.test:8443/");
        assert_eq!(config.realm, "himmelcloak-test");
        assert_eq!(config.client_id, "himmelcloak-test-client");
        assert_eq!(
            config.ca_bundle,
            Some(PathBuf::from("/work/tests/keycloak/.generated/ca.pem"))
        );
    }

    #[test]
    fn accepts_configuration_without_a_custom_ca() {
        let source = VALID
            .lines()
            .filter(|line| !line.starts_with("ca_bundle"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(parse_login_config(&source).unwrap().ca_bundle.is_none());
    }

    #[test]
    fn rejects_missing_settings_and_insecure_issuers() {
        assert!(matches!(
            parse_login_config("[sync]\nrealm = 'test'\n"),
            Err("missing [login] settings")
        ));

        let insecure = VALID.replace("https://", "http://");
        assert!(matches!(
            parse_login_config(&insecure),
            Err("invalid login configuration")
        ));

        let missing_client = VALID
            .lines()
            .filter(|line| !line.starts_with("client_id"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(matches!(
            parse_login_config(&missing_client),
            Err("invalid [login] settings")
        ));
    }

    #[test]
    fn configuration_errors_do_not_echo_sensitive_values() {
        let marker = "DO-NOT-PRINT-THIS-SECRET";

        let unknown_field = format!("{VALID}\npassword = '{marker}'\n");
        assert_eq!(
            parse_login_config(&unknown_field).err(),
            Some("invalid [login] settings")
        );

        let malformed = format!("{VALID}\npassword = '{marker}");
        assert_eq!(
            parse_login_config(&malformed).err(),
            Some("malformed configuration")
        );

        let credentials = VALID.replace(
            "https://keycloak.test",
            &format!("https://user:{marker}@keycloak.test"),
        );
        assert_eq!(
            parse_login_config(&credentials).err(),
            Some("invalid login configuration")
        );
    }
}
