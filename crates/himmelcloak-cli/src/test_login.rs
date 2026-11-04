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
    let source = Zeroizing::new(
        fs::read_to_string(path).map_err(|_| "cannot read configuration")?,
    );
    let document: toml::Value =
        toml::from_str(&source).map_err(|_| "malformed configuration")?;
    let settings: LoginSettings = document
        .get("login")
        .ok_or("missing [login] settings")?
        .clone()
        .try_into()
        .map_err(|_| "invalid [login] settings")?;

    let mut config = Config::new(
        &settings.server_url,
        &settings.realm,
        &settings.client_id,
    )
    .map_err(|_| "invalid login configuration")?;
    config.ca_bundle = settings.ca_bundle;
    Ok(config)
}