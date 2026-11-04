use std::io::{self, Write};
use std::{fs, path::Path, path::PathBuf};

use himmelcloak::config::Config;
use serde::Deserialize;
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
    let document: toml::Value = toml::from_str(&source).map_err(|_| "malformed configuration")?;
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
