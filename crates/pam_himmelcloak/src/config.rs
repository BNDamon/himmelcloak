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
//! Sprint 2 parses TOML syntax; client settings and identity rules are validated later.
//!
//! A parsed document is not permission to authenticate. Unknown keys and sections are
//! retained until the shared settings schema is finalized in HC-41.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/himmelcloak/himmelcloak.toml";
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// Syntactically valid TOML, not yet validated runtime or account-mapping settings.
pub struct ConfigDocument {
    table: toml::Table,
}

#[derive(Debug)]
pub enum ConfigError {
    Read(io::Error),
    TooLarge,
    Malformed,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TOML diagnostics can echo entire input lines, including sensitive values.
        f.write_str(match self {
            Self::Read(_) => "Cannot read Himmelcloak configuration",
            Self::TooLarge => "Himmelcloak configuration exceeds 64 KiB",
            Self::Malformed => "Malformed Himmelcloak TOML configuration",
        })
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            _ => None,
        }
    }
}

impl ConfigDocument {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        if input.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        let table = toml::from_str(input).map_err(|_| ConfigError::Malformed)?;
        Ok(Self { table })
    }

    /// Read at most the limit plus one byte, so an oversized file is never read fully.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let mut input = String::new();
        File::open(path)
            .map_err(ConfigError::Read)?
            .take(MAX_CONFIG_BYTES as u64 + 1)
            .read_to_string(&mut input)
            .map_err(ConfigError::Read)?;
        Self::parse(&input)
    }

    pub fn as_table(&self) -> &toml::Table {
        &self.table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn accepts_the_cli_skeletons_flat_example() {
        let document = ConfigDocument::parse("realm = 'himmelcloak-test'\n").unwrap();
        assert_eq!(
            document.as_table()["realm"].as_str(),
            Some("himmelcloak-test")
        );
    }

    #[test]
    fn preserves_sections_and_values_without_imposing_a_settings_schema() {
        let document =
            ConfigDocument::parse("[keycloak]\nrealm = 'test'\n[identity]\nrule = 'future-rule'\n")
                .unwrap();
        assert_eq!(
            document.as_table()["keycloak"]["realm"].as_str(),
            Some("test")
        );
        assert_eq!(
            document.as_table()["identity"]["rule"].as_str(),
            Some("future-rule")
        );
    }

    #[test]
    fn syntax_success_does_not_claim_that_runtime_settings_are_valid() {
        for input in ["", "# Empty TOML document\n", "realm = 42\n"] {
            assert!(ConfigDocument::parse(input).is_ok());
        }
    }

    #[test]
    fn rejects_malformed_toml_and_duplicate_keys() {
        for input in [
            "[keycloak",
            "realm = [\n",
            "realm = 'unterminated",
            "realm = 'one'\nrealm = 'two'\n",
            "value = 1\n[value]\nother = 2\n",
        ] {
            assert!(matches!(
                ConfigDocument::parse(input),
                Err(ConfigError::Malformed)
            ));
        }
    }

    #[test]
    fn enforces_the_size_limit_inclusively() {
        let mut input = String::from("realm = 'test'\n#");
        input.push_str(&"x".repeat(MAX_CONFIG_BYTES - input.len()));
        assert!(ConfigDocument::parse(&input).is_ok());
        input.push('x');
        assert!(matches!(
            ConfigDocument::parse(&input),
            Err(ConfigError::TooLarge)
        ));
        assert_eq!(
            ConfigError::TooLarge.to_string(),
            "Himmelcloak configuration exceeds 64 KiB"
        );
    }

    #[test]
    fn parse_errors_do_not_expose_source_values() {
        let error = match ConfigDocument::parse("secret = 'private-value") {
            Err(error) => error,
            Ok(_) => panic!("accepted malformed TOML"),
        };
        assert!(!error.to_string().contains("private-value"));
        assert!(error.source().is_none());
    }

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    struct TestFile(std::path::PathBuf);
    impl TestFile {
        fn new() -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            Self(std::env::temp_dir().join(format!(
                "himmelcloak-config-{}-{unique}-{}.toml",
                std::process::id(),
                NEXT_FILE.fetch_add(1, Ordering::Relaxed)
            )))
        }
    }
    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn loads_valid_and_rejects_malformed_files_without_touching_system_config() {
        let file = TestFile::new();
        std::fs::write(&file.0, "realm = 'test'\n").unwrap();
        assert_eq!(
            ConfigDocument::load(&file.0).unwrap().as_table()["realm"].as_str(),
            Some("test")
        );
        std::fs::write(&file.0, "[broken").unwrap();
        assert!(matches!(
            ConfigDocument::load(&file.0),
            Err(ConfigError::Malformed)
        ));
    }

    #[test]
    fn rejects_missing_and_non_utf8_files() {
        let file = TestFile::new();
        let error = match ConfigDocument::load(&file.0) {
            Err(error) => error,
            Ok(_) => panic!("loaded a nonexistent file"),
        };
        assert!(matches!(error, ConfigError::Read(_)));
        assert!(error.source().is_some());
        assert_eq!(error.to_string(), "Cannot read Himmelcloak configuration");
        std::fs::write(&file.0, [0xff, 0xfe]).unwrap();
        assert!(matches!(
            ConfigDocument::load(&file.0),
            Err(ConfigError::Read(_))
        ));
    }

    #[test]
    fn refuses_oversized_files() {
        let file = TestFile::new();
        std::fs::write(&file.0, " ".repeat(MAX_CONFIG_BYTES + 100)).unwrap();
        assert!(matches!(
            ConfigDocument::load(&file.0),
            Err(ConfigError::TooLarge)
        ));
    }
}
