/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) 2026 Damon Bun, Joshua Conklin, Kevin Torrecampo,
 * Aidan Garske, Harrison Barrett, and Harman Samra
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! Read-only group synchronization for the existing CLI command.
use himmelcloak::{admin::read_allowed_group, config::Config};
use serde::Deserialize;
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

type SyncResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncSettings {
    server_url: String,
    realm: String,
    client_id: String,
    allowed_group_id: String,
    client_secret_file: PathBuf,
    ca_bundle: Option<PathBuf>,
}

impl SyncSettings {
    fn core_config(&self) -> SyncResult<Config> {
        let mut config = Config::new(&self.server_url, &self.realm, &self.client_id)?;
        config.ca_bundle = self.ca_bundle.clone();
        Ok(config)
    }
}

fn parse_settings(source: &str) -> SyncResult<SyncSettings> {
    let document: toml::Value =
        toml::from_str(source).map_err(|_| "malformed sync configuration")?;
    let settings: SyncSettings = document
        .get("sync")
        .ok_or("missing [sync] settings")?
        .clone()
        .try_into()
        .map_err(|_| "invalid [sync] settings")?;
    if settings.allowed_group_id.trim().is_empty()
        || !settings.client_secret_file.is_absolute()
        || settings
            .ca_bundle
            .as_ref()
            .is_some_and(|p| !p.is_absolute())
    {
        return Err("sync group ID and absolute file paths are required".into());
    }
    settings.core_config()?;
    Ok(settings)
}

/// Root's configuration must not be writable by another user; its secret is stricter.
/// O_NOFOLLOW and metadata checks are applied to the same opened descriptor.
fn read_owned_file(path: &Path, secret: bool) -> SyncResult<Zeroizing<String>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "cannot open sync configuration or secret file")?;
    let meta = file.metadata().map_err(|_| "cannot inspect sync file")?;
    let size_limit = if secret { 16_384 } else { 65_536 };
    let mode = meta.mode() & 0o777;
    let bad_permissions = if secret {
        !matches!(mode, 0o600 | 0o400)
    } else {
        mode & 0o022 != 0
    };
    if !meta.is_file() || meta.uid() != 0 || bad_permissions || meta.len() > size_limit {
        return Err("sync files must be root-owned regular files; config must not be group/other writable, secret must be 0600/0400, and file size limits apply".into());
    }
    let mut value = read_bounded(file, size_limit)?;
    if secret {
        let length = value.trim_end_matches(['\r', '\n']).len();
        value.truncate(length);
        if value.is_empty() {
            return Err("service-account secret is empty".into());
        }
    }
    Ok(value)
}

/// The descriptor's contents may grow after metadata was checked.
fn read_bounded(reader: impl Read, limit: u64) -> SyncResult<Zeroizing<String>> {
    let mut value = Zeroizing::new(String::new());
    reader
        .take(limit + 1)
        .read_to_string(&mut value)
        .map_err(|_| "cannot read sync file")?;
    if value.len() as u64 > limit {
        return Err("sync file is too large".into());
    }
    Ok(value)
}

fn require_root(effective_uid: u32) -> SyncResult<()> {
    if effective_uid != 0 {
        return Err("sync-users must run as root".into());
    }
    Ok(())
}

pub fn run(path: &Path) -> SyncResult<()> {
    // SAFETY: geteuid has no pointer arguments or preconditions.
    require_root(unsafe { libc::geteuid() })?;
    let source = read_owned_file(path, false)?;
    let settings = parse_settings(&source)?;
    let secret = read_owned_file(&settings.client_secret_file, true)?;
    let config = settings.core_config()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let members = runtime.block_on(read_allowed_group(
        &config,
        &settings.allowed_group_id,
        &secret,
    ))?;
    // Serialize only after the complete group fetch succeeds.
    println!("{}", serde_json::to_string(&members)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };

    const CONFIG: &str = "realm = 'unrelated-top-level-setting'\n[sync]\nserver_url = 'https://keycloak.example'\nrealm = 'test'\nclient_id = 'sync-client'\nallowed_group_id = 'allowed'\nclient_secret_file = '/etc/himmelcloak/admin-client.secret'\n";

    #[test]
    fn root_requirement_rejects_ordinary_and_nobody_users() {
        assert!(require_root(0).is_ok());
        for uid in [1, 1000, 65534] {
            assert!(require_root(uid).is_err());
        }
    }

    #[test]
    fn bounded_reader_rejects_growth_and_invalid_utf8_without_partial_values() {
        assert_eq!(
            read_bounded(std::io::Cursor::new(b"ok"), 2)
                .unwrap()
                .as_str(),
            "ok"
        );
        assert!(read_bounded(std::io::Cursor::new(b"grew"), 2).is_err());
        assert!(read_bounded(std::io::Cursor::new([0xff]), 2).is_err());
    }

    #[test]
    fn reads_only_the_sync_table_and_preserves_other_cli_settings() {
        let settings = parse_settings(CONFIG).unwrap();
        assert_eq!(settings.allowed_group_id, "allowed");
        assert_eq!(settings.core_config().unwrap().realm, "test");
    }

    #[test]
    fn rejects_missing_malformed_unknown_and_insecure_sync_settings() {
        for source in [
            "realm = 'test'".to_owned(),
            "[sync".to_owned(),
            CONFIG.replace("allowed_group_id = 'allowed'\n", ""),
            CONFIG.replace("allowed_group_id = 'allowed'", "allowed_group_id = 3"),
            CONFIG.replace("allowed_group_id = 'allowed'", "allowed_group_id = '   '"),
            CONFIG.replace("https://", "http://"),
            CONFIG.replace(
                "'/etc/himmelcloak/admin-client.secret'",
                "'relative.secret'",
            ),
            format!("{CONFIG}unknown = true"),
            format!("{CONFIG}ca_bundle = 'relative.pem'"),
        ] {
            assert!(parse_settings(&source).is_err());
        }
    }

    #[test]
    fn file_checks_enforce_ownership_permissions_and_no_symlinks() {
        let directory =
            std::env::temp_dir().join(format!("hc49-owned-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("secret");
        fs::write(&path, "fixture-secret\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_owned_file(&path, false).is_err());
        assert!(read_owned_file(&path, true).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_owned_file(&path, true).is_err());
        // SAFETY: geteuid has no pointer arguments or preconditions.
        if unsafe { libc::geteuid() } == 0 {
            assert!(read_owned_file(&path, false).is_ok());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(
                read_owned_file(&path, true).unwrap().as_str(),
                "fixture-secret"
            );
            fs::write(&path, "").unwrap();
            assert!(read_owned_file(&path, true).is_err());
            fs::write(&path, "x".repeat(16_385)).unwrap();
            assert!(read_owned_file(&path, true).is_err());
        }
        // The ownership rule also applies when this test is run by a non-root user.
        assert_eq!(
            read_owned_file(&path, false).is_ok(),
            unsafe { libc::geteuid() } == 0
        );
        let link = directory.join("link");
        symlink(&path, &link).unwrap();
        assert!(read_owned_file(&link, false).is_err());
        assert!(read_owned_file(&directory, false).is_err());
        fs::remove_file(link).unwrap();
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
