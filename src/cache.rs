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
//! Sealed on-disk token cache (charter section 2.3 item 6a).
//!
//! Keeps a signed-in session's tokens across a process restart without storing them in the
//! clear. The cache never grants access by itself: a cached session is only a starting point for
//! talking to Keycloak (refresh, user information), and offline login stays outside scope.
//!
//! - The cache directory, each entry, and the key file must belong to root and allow no access
//!   to group or others; otherwise the cache refuses to work.
//! - Each entry is AES-256-GCM encrypted under a fresh random nonce. The format version, the
//!   expiry time, and the hash of the user's name are authenticated with it, so an entry cannot
//!   be edited, given a later expiry, or moved to another user's name.
//! - An expired entry is refused. It is left in place for the next `store` to replace, so a
//!   load never deletes a session another process has just saved.
//! - The key, the encoded tokens, and the decrypted entry live in buffers wiped when dropped.
//!
//! The key file is on the same machine, so this protects copies of the cache (a backup, a copied
//! directory) but not a reader who is already root. Hardware sealing is the `hsm-seal` package.
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::{Zeroize, Zeroizing};

use crate::crypto;
use crate::error::{Error, Result};
use crate::flow::Tokens;

/// Format version, authenticated with every entry.
const MAGIC: &[u8; 4] = b"HCC1";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const EXPIRY_LEN: usize = 8;
const HEADER_LEN: usize = MAGIC.len() + EXPIRY_LEN + NONCE_LEN + TAG_LEN;
const MAX_ENTRY: u64 = 256 * 1024;
/// The largest encoded tokens that still fit in an entry `load` accepts. AES-GCM ciphertext is
/// the same length as its plaintext.
const MAX_PLAINTEXT: usize = MAX_ENTRY as usize - HEADER_LEN;
const ROOT: u32 = 0;
/// Group and other permission bits; none may be set.
const SHARED_BITS: u32 = 0o077;
/// Group and other write bits; none may be set on the key's directory.
const WRITE_BITS: u32 = 0o022;
/// The token fields an entry holds, in order.
const FIELDS: usize = 7;

const PRIVATE_DIR: Error =
    Error::InvalidConfiguration("token cache directory must belong to root and be private");
const PRIVATE_KEY: Error = Error::InvalidConfiguration(
    "token cache key must belong to root, be private, and hold 32 bytes",
);
const PRIVATE_KEY_DIR: Error = Error::InvalidConfiguration(
    "token cache key directory must belong to root and not be writable by group or others",
);
const PRIVATE_ENTRY: Error =
    Error::InvalidConfiguration("token cache entry must belong to root and be private");
const MALFORMED: Error = Error::Protocol("malformed token cache entry");
const BEFORE_1970: Error = Error::InvalidConfiguration("time before 1970");
const TOO_LARGE: Error = Error::InvalidConfiguration("token too large to cache");

/// An encrypted, root-only store of verified sessions, one entry per user.
pub struct TokenCache {
    dir: PathBuf,
    key: Zeroizing<[u8; KEY_LEN]>,
    owner: u32,
}

impl TokenCache {
    /// Open the cache in `dir`, encrypting with the key in `key_file`. Creates the directory
    /// (mode 0700) and a new random key (mode 0600) when they do not exist yet. The key file's
    /// parent directory must already exist, belong to root, and not be writable by group or
    /// others: otherwise someone could delete the key, and the next open would quietly create
    /// a new one that no saved entry opens under.
    pub fn open(dir: &Path, key_file: &Path) -> Result<Self> {
        Self::open_owned_by(dir, key_file, ROOT)
    }

    /// `open`, for a cache that must belong to `owner` rather than root. Tests use it to run
    /// without root.
    fn open_owned_by(dir: &Path, key_file: &Path, owner: u32) -> Result<Self> {
        match DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(_) => return Err(PRIVATE_DIR),
        }
        let metadata = fs::symlink_metadata(dir).map_err(|_| PRIVATE_DIR)?;
        if !metadata.is_dir() || !private(&metadata, owner) {
            return Err(PRIVATE_DIR);
        }
        let key = load_key(key_file, owner)?;
        Ok(Self {
            dir: dir.to_owned(),
            key,
            owner,
        })
    }

    /// Save `user`'s tokens, replacing any earlier entry. The entry is refused after
    /// `expires_at`, which must be in the future. Tokens too large for `load` to accept are
    /// refused with `InvalidConfiguration`, and the earlier entry is kept.
    ///
    /// `expires_at` is the caller's choice and is not tied to the tokens' own lifetimes, so an
    /// entry can outlive the refresh token it holds. That is harmless, since Keycloak still
    /// rejects the session when it is refreshed, but callers should not pass a later time
    /// than the refresh token's expiry.
    pub fn store(&self, user: &str, tokens: &Tokens, expires_at: SystemTime) -> Result<()> {
        let expires = unix_seconds(expires_at)?;
        if expires <= unix_seconds(SystemTime::now())? {
            return Err(Error::Expired);
        }
        let name = crypto::sha256(user.as_bytes())?;
        let plaintext = encode(tokens)?;
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(TOO_LARGE);
        }
        let nonce = crypto::random_bytes::<NONCE_LEN>()?;
        let (ciphertext, tag) =
            crypto::aes_gcm_seal(&*self.key, &*nonce, &aad(expires, &name), &plaintext)?;
        let mut entry = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        entry.extend_from_slice(MAGIC);
        entry.extend_from_slice(&expires.to_be_bytes());
        entry.extend_from_slice(&*nonce);
        entry.extend_from_slice(&tag);
        entry.extend_from_slice(&ciphertext);
        self.write(&name, &entry)
    }

    /// `user`'s saved tokens, or `None` when nothing is saved. An expired entry is refused with
    /// `Expired` and left for the next `store` to replace. An entry that fails AES-GCM
    /// verification (altered, saved under another user's name, or sealed with another key) is
    /// refused with `Crypto`; a malformed or unsupported one (wrong version, truncated, or too
    /// large) with `Protocol`.
    pub fn load(&self, user: &str) -> Result<Option<Tokens>> {
        self.load_at(user, SystemTime::now())
    }

    fn load_at(&self, user: &str, now: SystemTime) -> Result<Option<Tokens>> {
        let name = crypto::sha256(user.as_bytes())?;
        let path = self.path(&name);
        let mut file = match open_no_follow(&path) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            opened => opened.map_err(|_| PRIVATE_ENTRY)?,
        };
        let metadata = file.metadata().map_err(|_| PRIVATE_ENTRY)?;
        if !metadata.is_file() || !private(&metadata, self.owner) {
            return Err(PRIVATE_ENTRY);
        }
        if metadata.len() > MAX_ENTRY {
            return Err(MALFORMED);
        }
        let mut entry = Vec::new();
        file.read_to_end(&mut entry).map_err(|_| MALFORMED)?;
        if entry.len() < HEADER_LEN || &entry[..MAGIC.len()] != MAGIC {
            return Err(MALFORMED);
        }
        let (expiry, rest) = entry[MAGIC.len()..].split_at(EXPIRY_LEN);
        let (nonce, rest) = rest.split_at(NONCE_LEN);
        let (tag, ciphertext) = rest.split_at(TAG_LEN);
        let mut expires = [0u8; EXPIRY_LEN];
        expires.copy_from_slice(expiry);
        let expires = u64::from_be_bytes(expires);
        // Decrypting first proves the expiry time was not edited.
        let plaintext =
            crypto::aes_gcm_open(&*self.key, nonce, &aad(expires, &name), ciphertext, tag)?;
        // Not deleted here: another process may have replaced this file since it was opened,
        // and deleting by name would remove that newer session.
        if unix_seconds(now)? >= expires {
            return Err(Error::Expired);
        }
        decode(&plaintext).map(Some)
    }

    /// Delete `user`'s entry, if there is one.
    pub fn remove(&self, user: &str) -> Result<()> {
        let name = crypto::sha256(user.as_bytes())?;
        match fs::remove_file(self.path(&name)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(_) => Err(PRIVATE_ENTRY),
        }
    }

    /// An entry is named by the hash of its user's name, so no name can reach outside `dir`.
    fn path(&self, name: &[u8; 32]) -> PathBuf {
        self.dir.join(hex(name))
    }

    /// Write through a new private file renamed into place, so a crash never leaves a partial
    /// entry behind. The directory is synced after the rename so the new entry survives a
    /// crash too.
    fn write(&self, name: &[u8; 32], entry: &[u8]) -> Result<()> {
        let suffix = crypto::random_bytes::<8>()?;
        let temporary = self.dir.join(format!(".{}.tmp", hex(&*suffix)));
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .and_then(|mut file| file.write_all(entry).and_then(|()| file.sync_all()))
            .and_then(|()| fs::rename(&temporary, self.path(name)))
            .and_then(|()| sync_dir(&self.dir));
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        written.map_err(|_| PRIVATE_ENTRY)
    }
}

/// Read the key, or create a new random one when `path` does not exist. The key's directory
/// must belong to `owner` and not be writable by group or others.
fn load_key(path: &Path, owner: u32) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let parent = fs::metadata(parent(path)).map_err(|_| PRIVATE_KEY_DIR)?;
    if !parent.is_dir() || parent.uid() != owner || parent.mode() & WRITE_BITS != 0 {
        return Err(PRIVATE_KEY_DIR);
    }
    let file = match open_no_follow(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return create_key(path, owner),
        opened => opened.map_err(|_| PRIVATE_KEY)?,
    };
    read_key(file, owner)
}

/// Write a new random key to a private temporary file, then publish it at `path` only once it
/// is complete and on disk, so a failure never leaves a partial key behind. A hard link refuses
/// to replace an existing file: when another process created the key first, its key is used.
/// The directory is synced after the link, so a crash cannot lose a key entries were sealed
/// under.
fn create_key(path: &Path, owner: u32) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let key = crypto::random_bytes::<KEY_LEN>()?;
    let suffix = crypto::random_bytes::<8>()?;
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(".{}.tmp", hex(&*suffix)));
    let temporary = PathBuf::from(temporary);
    let published = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .and_then(|mut file| file.write_all(&*key).and_then(|()| file.sync_all()))
        .and_then(|()| fs::hard_link(&temporary, path))
        .and_then(|()| sync_dir(parent(path)));
    let _ = fs::remove_file(&temporary);
    match published {
        Ok(()) => Ok(key),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let file = open_no_follow(path).map_err(|_| PRIVATE_KEY)?;
            read_key(file, owner)
        }
        Err(_) => Err(PRIVATE_KEY),
    }
}

/// An existing key: a private file of exactly `KEY_LEN` bytes.
fn read_key(mut file: File, owner: u32) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let metadata = file.metadata().map_err(|_| PRIVATE_KEY)?;
    if !metadata.is_file() || !private(&metadata, owner) || metadata.len() != KEY_LEN as u64 {
        return Err(PRIVATE_KEY);
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    file.read_exact(&mut *key).map_err(|_| PRIVATE_KEY)?;
    Ok(key)
}

/// Open for reading without following a symlink, so `path` itself must be the file. A FIFO or
/// device does not block the open; the caller's `is_file` check then refuses it.
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

/// The directory holding `path`; the current directory for a bare file name.
fn parent(path: &Path) -> &Path {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    parent.unwrap_or(Path::new("."))
}

/// Make a rename or link inside `dir` durable.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Owned by `owner`, with no permission for group or others.
fn private(metadata: &Metadata, owner: u32) -> bool {
    metadata.uid() == owner && metadata.mode() & SHARED_BITS == 0
}

/// The data authenticated with an entry: its version, expiry, and user.
fn aad(expires: u64, name: &[u8; 32]) -> Vec<u8> {
    [&MAGIC[..], &expires.to_be_bytes(), name].concat()
}

fn unix_seconds(time: SystemTime) -> Result<u64> {
    let elapsed = time.duration_since(UNIX_EPOCH).map_err(|_| BEFORE_1970)?;
    Ok(elapsed.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Each field as a presence byte, then a 4-byte big-endian length and its bytes.
fn encode(tokens: &Tokens) -> Result<Zeroizing<Vec<u8>>> {
    let fields: [Option<&str>; FIELDS] = [
        Some(&tokens.access_token),
        tokens.refresh_token.as_deref(),
        tokens.id_token.as_deref(),
        tokens.verified_subject.as_deref(),
        tokens.verified_issuer.as_deref(),
        tokens.verified_client_id.as_deref(),
        tokens.verified_refresh_token.as_deref(),
    ];
    // Reserve everything up front so no secret is left behind in a reallocated buffer.
    let size = fields
        .iter()
        .map(|field| 1 + field.map_or(0, |text| 4 + text.len()))
        .sum();
    let mut out = Zeroizing::new(Vec::with_capacity(size));
    for field in fields {
        match field {
            None => out.push(0),
            Some(text) => {
                let len = u32::try_from(text.len()).map_err(|_| TOO_LARGE)?;
                out.push(1);
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(text.as_bytes());
            }
        }
    }
    Ok(out)
}

fn decode(mut input: &[u8]) -> Result<Tokens> {
    // Wiped on every return, including a malformed entry that fails part way.
    let mut fields: Zeroizing<[Option<String>; FIELDS]> = Zeroizing::new(Default::default());
    for field in fields.iter_mut() {
        *field = next_field(&mut input)?;
    }
    if !input.is_empty() || fields[0].is_none() {
        return Err(MALFORMED);
    }
    Ok(Tokens {
        access_token: fields[0].take().unwrap_or_default(),
        refresh_token: fields[1].take(),
        id_token: fields[2].take(),
        verified_subject: fields[3].take(),
        verified_issuer: fields[4].take(),
        verified_client_id: fields[5].take(),
        verified_refresh_token: fields[6].take(),
    })
}

fn next_field(input: &mut &[u8]) -> Result<Option<String>> {
    let (&present, rest) = input.split_first().ok_or(MALFORMED)?;
    *input = rest;
    match present {
        0 => return Ok(None),
        1 => {}
        _ => return Err(MALFORMED),
    }
    if input.len() < 4 {
        return Err(MALFORMED);
    }
    let (len, rest) = input.split_at(4);
    let len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
    if rest.len() < len {
        return Err(MALFORMED);
    }
    let (text, rest) = rest.split_at(len);
    *input = rest;
    String::from_utf8(text.to_vec())
        .map(Some)
        .map_err(|invalid| {
            invalid.into_bytes().zeroize();
            MALFORMED
        })
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File, OpenOptions};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    use zeroize::Zeroizing;

    use super::{
        create_key, decode, encode, hex, TokenCache, MAGIC, MALFORMED, PRIVATE_DIR, PRIVATE_ENTRY,
        PRIVATE_KEY, PRIVATE_KEY_DIR, TOO_LARGE,
    };
    use crate::crypto;
    use crate::error::Error;
    use crate::flow::Tokens;

    const ACCESS: &str = "synthetic-access-token";

    /// A fresh private directory holding `cache/` and `key`, removed when dropped.
    struct Scratch {
        base: PathBuf,
        /// The test process's own user, which owns everything it creates.
        me: u32,
    }

    impl Scratch {
        fn new() -> Self {
            let suffix = crypto::random_bytes::<16>().unwrap();
            let base = std::env::temp_dir().join(format!("himmelcloak-cache-{}", hex(&*suffix)));
            fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
            let me = fs::metadata(&base).unwrap().uid();
            Self { base, me }
        }

        fn dir(&self) -> PathBuf {
            self.base.join("cache")
        }

        fn key(&self) -> PathBuf {
            self.base.join("key")
        }

        fn open(&self) -> crate::error::Result<TokenCache> {
            TokenCache::open_owned_by(&self.dir(), &self.key(), self.me)
        }

        /// The one entry file in the cache directory.
        fn entry(&self) -> PathBuf {
            let mut entries: Vec<_> = fs::read_dir(self.dir())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            assert_eq!(
                entries.len(),
                1,
                "exactly one entry, and no leftover temporary file"
            );
            entries.remove(0)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    fn tokens() -> Tokens {
        Tokens {
            access_token: ACCESS.to_owned(),
            refresh_token: Some("synthetic-refresh-token".to_owned()),
            id_token: Some("synthetic-id-token".to_owned()),
            verified_subject: Some("alice-subject".to_owned()),
            verified_issuer: Some("https://keycloak.test:8443/realms/himmelcloak-test".to_owned()),
            verified_client_id: Some("himmelcloak-cli".to_owned()),
            verified_refresh_token: Some("synthetic-refresh-token".to_owned()),
        }
    }

    fn fields(tokens: &Tokens) -> [Option<String>; 7] {
        [
            Some(tokens.access_token.clone()),
            tokens.refresh_token.clone(),
            tokens.id_token.clone(),
            tokens.verified_subject.clone(),
            tokens.verified_issuer.clone(),
            tokens.verified_client_id.clone(),
            tokens.verified_refresh_token.clone(),
        ]
    }

    fn in_an_hour() -> SystemTime {
        SystemTime::now() + Duration::from_secs(3600)
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o777
    }

    #[test]
    fn a_saved_session_survives_a_restart() {
        let scratch = Scratch::new();
        scratch
            .open()
            .unwrap()
            .store("alice", &tokens(), in_an_hour())
            .unwrap();

        // A new process: the cache and its key are opened again from disk.
        let cache = scratch.open().unwrap();
        let loaded = cache.load("alice").unwrap().unwrap();
        assert_eq!(fields(&loaded), fields(&tokens()));
        assert!(cache.load("bob").unwrap().is_none());

        // Absent optional tokens stay absent.
        let mut minimal = tokens();
        minimal.refresh_token = None;
        minimal.id_token = None;
        minimal.verified_refresh_token = None;
        cache.store("alice", &minimal, in_an_hour()).unwrap();
        assert_eq!(
            fields(&cache.load("alice").unwrap().unwrap()),
            fields(&minimal)
        );

        cache.remove("alice").unwrap();
        assert!(cache.load("alice").unwrap().is_none());
        cache.remove("alice").unwrap();
    }

    #[test]
    fn the_cache_is_private_and_its_entries_are_encrypted() {
        let scratch = Scratch::new();
        let cache = scratch.open().unwrap();
        cache.store("alice", &tokens(), in_an_hour()).unwrap();
        assert_eq!(mode(&scratch.dir()), 0o700);
        assert_eq!(mode(&scratch.key()), 0o600);
        let entry = scratch.entry();
        assert_eq!(mode(&entry), 0o600);
        // The file is named by a hash, never by the user's name.
        assert!(!entry.to_string_lossy().contains("alice"));

        let bytes = fs::read(&entry).unwrap();
        assert!(bytes.starts_with(MAGIC));
        for secret in fields(&tokens()).into_iter().flatten() {
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
                "no token may appear in the clear on disk"
            );
        }
        // A fresh nonce each time: saving the same tokens again writes different bytes.
        cache.store("alice", &tokens(), in_an_hour()).unwrap();
        assert_ne!(fs::read(scratch.entry()).unwrap(), bytes);
    }

    #[test]
    fn only_a_root_only_cache_opens() {
        let scratch = Scratch::new();
        scratch.open().unwrap();

        // `open` requires root to own the cache.
        let as_root = TokenCache::open(&scratch.dir(), &scratch.key());
        assert_eq!(as_root.is_ok(), scratch.me == 0);
        // Another owner, or access for group or others, is refused.
        assert_eq!(
            TokenCache::open_owned_by(&scratch.dir(), &scratch.key(), scratch.me + 1).err(),
            Some(PRIVATE_DIR)
        );
        fs::set_permissions(scratch.dir(), fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(scratch.open().err(), Some(PRIVATE_DIR));
        fs::set_permissions(scratch.dir(), fs::Permissions::from_mode(0o700)).unwrap();

        fs::set_permissions(scratch.key(), fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(scratch.open().err(), Some(PRIVATE_KEY));
        fs::set_permissions(scratch.key(), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(scratch.open().is_ok());
    }

    #[test]
    fn a_bad_directory_or_key_is_refused() {
        // The cache path is a file, or its parent is missing.
        let scratch = Scratch::new();
        File::create(scratch.dir()).unwrap();
        assert_eq!(scratch.open().err(), Some(PRIVATE_DIR));
        let missing = scratch.base.join("missing").join("cache");
        assert_eq!(
            TokenCache::open_owned_by(&missing, &scratch.key(), scratch.me).err(),
            Some(PRIVATE_DIR)
        );

        // The key has the wrong size, is a directory, or its parent is missing.
        let scratch = Scratch::new();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(scratch.key())
            .unwrap();
        assert_eq!(scratch.open().err(), Some(PRIVATE_KEY));
        fs::remove_file(scratch.key()).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(scratch.key())
            .unwrap();
        assert_eq!(scratch.open().err(), Some(PRIVATE_KEY));
        let missing = scratch.base.join("missing").join("key");
        assert_eq!(
            TokenCache::open_owned_by(&scratch.dir(), &missing, scratch.me).err(),
            Some(PRIVATE_KEY_DIR)
        );
        // Creating a key where none can be written fails cleanly too.
        assert_eq!(create_key(&missing, scratch.me).err(), Some(PRIVATE_KEY));
    }

    #[test]
    fn the_key_directory_must_not_let_others_replace_the_key() {
        let scratch = Scratch::new();
        let cache = scratch.open().unwrap();
        cache.store("alice", &tokens(), in_an_hour()).unwrap();

        // If group or others could write the key's directory, they could delete the key and
        // the next open would make a new one that no saved entry opens under.
        for mode in [0o770, 0o702] {
            fs::set_permissions(&scratch.base, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(scratch.open().err(), Some(PRIVATE_KEY_DIR));
        }
        fs::set_permissions(&scratch.base, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(scratch.open().is_ok(), "readable by others is fine");
        fs::set_permissions(&scratch.base, fs::Permissions::from_mode(0o700)).unwrap();

        // Another owner, or a key "directory" that is a file, is refused too.
        assert_eq!(
            super::load_key(&scratch.key(), scratch.me + 1).err(),
            Some(PRIVATE_KEY_DIR)
        );
        let inside_a_file = scratch.key().join("key");
        assert_eq!(
            super::load_key(&inside_a_file, scratch.me).err(),
            Some(PRIVATE_KEY_DIR)
        );

        // A bare file name is checked against the current directory.
        assert_eq!(super::parent(Path::new("key")), Path::new("."));
        assert_eq!(super::parent(&scratch.key()), scratch.base);
        assert!(scratch.open().unwrap().load("alice").unwrap().is_some());
    }

    #[test]
    fn symlinks_are_never_followed() {
        let scratch = Scratch::new();
        let cache = scratch.open().unwrap();
        cache.store("alice", &tokens(), in_an_hour()).unwrap();
        let entry = scratch.entry();

        // A link in place of a valid entry, pointing at a valid copy of it, is refused.
        let copy = scratch.base.join("copy");
        fs::rename(&entry, &copy).unwrap();
        std::os::unix::fs::symlink(&copy, &entry).unwrap();
        assert_eq!(cache.load("alice").err(), Some(PRIVATE_ENTRY));
        fs::remove_file(&entry).unwrap();
        fs::rename(&copy, &entry).unwrap();
        assert!(cache.load("alice").unwrap().is_some());

        // So is a link in place of the key.
        let key = scratch.base.join("real-key");
        fs::rename(scratch.key(), &key).unwrap();
        std::os::unix::fs::symlink(&key, scratch.key()).unwrap();
        assert_eq!(scratch.open().err(), Some(PRIVATE_KEY));
        // A process that loses the race to create the key does not follow one either.
        assert_eq!(
            create_key(&scratch.key(), scratch.me).err(),
            Some(PRIVATE_KEY)
        );
    }

    #[test]
    fn an_expired_entry_is_refused_until_replaced() {
        let scratch = Scratch::new();
        let cache = scratch.open().unwrap();
        let expires = in_an_hour();
        cache.store("alice", &tokens(), expires).unwrap();
        let expired = fs::read(scratch.entry()).unwrap();

        // Usable until its expiry, then refused from that second on.
        let before = expires - Duration::from_secs(2);
        assert!(cache.load_at("alice", before).unwrap().is_some());
        assert_eq!(cache.load_at("alice", expires).err(), Some(Error::Expired));
        // Refusing it does not delete it, so a load can never remove a session another
        // process saved in the meantime. The next store replaces it.
        assert_eq!(fs::read(scratch.entry()).unwrap(), expired);
        assert_eq!(cache.load_at("alice", expires).err(), Some(Error::Expired));
        let later = expires + Duration::from_secs(3600);
        cache.store("alice", &tokens(), later).unwrap();
        assert!(cache.load_at("alice", expires).unwrap().is_some());
        cache.remove("alice").unwrap();

        // An entry that would already be expired is never written.
        let past = SystemTime::now() - Duration::from_secs(1);
        assert_eq!(
            cache.store("alice", &tokens(), past).err(),
            Some(Error::Expired)
        );
        assert!(fs::read_dir(scratch.dir()).unwrap().next().is_none());
    }

    #[test]
    fn an_altered_or_moved_entry_is_refused() {
        let scratch = Scratch::new();
        let cache = scratch.open().unwrap();
        cache.store("alice", &tokens(), in_an_hour()).unwrap();
        let entry = scratch.entry();
        let original = fs::read(&entry).unwrap();

        // A changed ciphertext byte, or a later expiry written into the header.
        for index in [original.len() - 1, MAGIC.len() + 7] {
            let mut altered = original.clone();
            altered[index] ^= 1;
            fs::write(&entry, &altered).unwrap();
            assert_eq!(cache.load("alice").err(), Some(Error::Crypto));
        }

        // alice's entry copied under bob's name does not open as bob's.
        fs::write(&entry, &original).unwrap();
        let bob = scratch.dir().join(hex(&crypto::sha256(b"bob").unwrap()));
        fs::copy(&entry, &bob).unwrap();
        assert_eq!(cache.load("bob").err(), Some(Error::Crypto));

        // A different key cannot open it either.
        fs::remove_file(&bob).unwrap();
        fs::remove_file(scratch.key()).unwrap();
        let rekeyed = scratch.open().unwrap();
        assert_eq!(rekeyed.load("alice").err(), Some(Error::Crypto));
    }

    #[test]
    fn a_malformed_or_shared_entry_is_refused() {
        let scratch = Scratch::new();
        let cache = scratch.open().unwrap();
        cache.store("alice", &tokens(), in_an_hour()).unwrap();
        let entry = scratch.entry();
        let original = fs::read(&entry).unwrap();

        for malformed in [
            original[..super::HEADER_LEN - 1].to_vec(),
            [&b"XXXX"[..], &original[MAGIC.len()..]].concat(),
            vec![0u8; super::MAX_ENTRY as usize + 1],
        ] {
            fs::write(&entry, &malformed).unwrap();
            assert_eq!(cache.load("alice").err(), Some(MALFORMED));
        }

        fs::write(&entry, &original).unwrap();
        fs::set_permissions(&entry, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(cache.load("alice").err(), Some(PRIVATE_ENTRY));

        // A directory where the entry should be cannot be read, replaced, or removed.
        fs::remove_file(&entry).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&entry).unwrap();
        File::create(entry.join("occupied")).unwrap();
        assert_eq!(cache.load("alice").err(), Some(PRIVATE_ENTRY));
        assert_eq!(
            cache.store("alice", &tokens(), in_an_hour()).err(),
            Some(PRIVATE_ENTRY)
        );
        assert_eq!(cache.remove("alice").err(), Some(PRIVATE_ENTRY));
        let leftovers = fs::read_dir(scratch.dir()).unwrap().count();
        assert_eq!(leftovers, 1, "a failed write leaves no temporary file");
    }

    #[test]
    fn tokens_too_large_to_load_are_refused_and_the_old_entry_kept() {
        let scratch = Scratch::new();
        let cache = scratch.open().unwrap();
        cache.store("alice", &tokens(), in_an_hour()).unwrap();
        let saved = fs::read(scratch.entry()).unwrap();

        // Encoded, these tokens are exactly as large as an entry `load` accepts.
        let encoded_without_access = encode(&tokens()).unwrap().len() - ACCESS.len();
        let mut largest = tokens();
        largest.access_token = "a".repeat(super::MAX_PLAINTEXT - encoded_without_access);
        let mut oversized = tokens();
        oversized.access_token = format!("{}a", largest.access_token);

        assert_eq!(
            cache.store("alice", &oversized, in_an_hour()).err(),
            Some(TOO_LARGE)
        );
        assert_eq!(
            fs::read(scratch.entry()).unwrap(),
            saved,
            "the earlier entry is untouched"
        );
        cache.store("alice", &largest, in_an_hour()).unwrap();
        assert_eq!(
            fs::metadata(scratch.entry()).unwrap().len(),
            super::MAX_ENTRY
        );
        assert_eq!(
            cache.load("alice").unwrap().unwrap().access_token,
            largest.access_token
        );
    }

    #[test]
    fn a_key_is_published_whole_and_a_second_creator_uses_the_first_key() {
        let scratch = Scratch::new();
        let cache = scratch.open().unwrap();
        cache.store("alice", &tokens(), in_an_hour()).unwrap();
        let key = fs::read(scratch.key()).unwrap();

        // A process that lost the race to create the key reads the winner's key instead of
        // replacing it, so entries already sealed under it still open.
        let second = create_key(&scratch.key(), scratch.me).unwrap();
        assert_eq!(&second[..], &key[..]);
        assert_eq!(fs::read(scratch.key()).unwrap(), key);
        assert!(scratch.open().unwrap().load("alice").unwrap().is_some());

        // Only the key and the cache directory remain: no temporary key file is left behind.
        let mut names: Vec<_> = fs::read_dir(&scratch.base)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, ["cache", "key"]);

        // A temporary file left by a crashed creator does not block a later one.
        fs::remove_file(scratch.key()).unwrap();
        fs::write(scratch.base.join("key.0000000000000000.tmp"), b"partial").unwrap();
        assert!(scratch.open().is_ok());
        assert_eq!(fs::metadata(scratch.key()).unwrap().len(), 32);
    }

    #[test]
    fn decoding_refuses_malformed_plaintext() {
        let good = encode(&tokens()).unwrap();
        assert_eq!(fields(&decode(&good).unwrap()), fields(&tokens()));
        for bad in [
            Vec::new(),                 // no fields at all
            vec![2],                    // unknown presence byte
            vec![1, 0, 0],              // truncated length
            vec![1, 0, 0, 0, 9, b'x'],  // length past the end
            vec![1, 0, 0, 0, 1, 0xff],  // not UTF-8
            vec![0, 0, 0, 0, 0, 0, 0],  // no access token
            [&good[..], &[0]].concat(), // trailing bytes
        ] {
            assert_eq!(decode(&bad).err(), Some(MALFORMED), "{bad:?}");
        }
    }

    #[test]
    fn secret_buffers_are_wiped_when_dropped() {
        // The encoded tokens and the decrypted entry are `Zeroizing`, so they are overwritten
        // with zeros when dropped; this fails to compile if either becomes a plain buffer.
        let encoded: Zeroizing<Vec<u8>> = encode(&tokens()).unwrap();
        let key = [7u8; 32];
        let nonce = [1u8; 12];
        let (ciphertext, tag) = crypto::aes_gcm_seal(&key, &nonce, b"", &encoded).unwrap();
        let decrypted: Zeroizing<Vec<u8>> =
            crypto::aes_gcm_open(&key, &nonce, b"", &ciphertext, &tag).unwrap();
        assert_eq!(*decrypted, *encoded);
    }
}
