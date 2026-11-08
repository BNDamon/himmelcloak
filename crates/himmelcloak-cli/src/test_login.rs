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
static SAVED_TERMINAL: std::sync::Mutex<Option<libc::termios>> = std::sync::Mutex::new(None);

fn restore_terminal(action: libc::c_int) -> LoginResult<()> {
    let mut saved = SAVED_TERMINAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Some(original) = saved.as_ref() {
        // SAFETY: original was obtained from this terminal descriptor.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, action, original) } != 0 {
            return Err("cannot restore terminal settings");
        }
        *saved = None;
    }

    Ok(())
}

struct RestoreEcho;

impl Drop for RestoreEcho {
    fn drop(&mut self) {
        let _ = restore_terminal(libc::TCSAFLUSH);
    }
}

fn hide_echo() -> LoginResult<RestoreEcho> {
    let mut saved = SAVED_TERMINAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if saved.is_some() {
        return Err("password input is already active");
    }

    let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();

    // SAFETY: original points to writable storage for terminal settings.
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, original.as_mut_ptr()) } != 0 {
        return Err("password input requires an interactive terminal");
    }

    // SAFETY: tcgetattr initialized the settings on success.
    let original = unsafe { original.assume_init() };
    let mut settings = original;
    settings.c_lflag &= !(libc::ECHO | libc::ECHONL);

    // Save before changing echo. The mutex coordinates with the interrupt handler.
    *saved = Some(original);
    let guard = RestoreEcho;

    // SAFETY: settings contains initialized terminal settings.
    let result = unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &settings) };

    drop(saved);

    if result != 0 {
        drop(guard);
        return Err("cannot hide password input");
    }

    Ok(guard)
}

fn install_interrupt_handler() -> LoginResult<()> {
    ctrlc::try_set_handler(|| {
        let _ = restore_terminal(libc::TCSAFLUSH);
        std::process::exit(130);
    })
    .map_err(|_| "cannot install login interrupt handler")
}

fn read_input(prompt: &str, hidden: bool) -> LoginResult<Zeroizing<String>> {
    let restore = if hidden { Some(hide_echo()?) } else { None };

    let mut output = io::stdout();
    write!(output, "{prompt}").map_err(|_| "cannot write prompt")?;
    output.flush().map_err(|_| "cannot write prompt")?;

    let mut value = Zeroizing::new(String::new());
    let result = io::stdin().read_line(&mut value);

    if hidden {
        restore_terminal(libc::TCSANOW)?;
    }
    drop(restore);

    if hidden {
        writeln!(io::stdout()).map_err(|_| "cannot write prompt")?;
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
/// The fixed message for a login that could not start. It never includes server details.
fn start_error(error: &himmelcloak::Error) -> &'static str {
    match error {
        himmelcloak::Error::HttpStatus(_) => "cannot start login: unexpected HTTP status",
        himmelcloak::Error::Transport(_) | himmelcloak::Error::Unreachable(_) => {
            "cannot start login: transport failure"
        }
        himmelcloak::Error::Protocol(_) => "cannot start login: protocol failure",
        himmelcloak::Error::UnsupportedFactor => "cannot start login: unsupported factor",
        himmelcloak::Error::Crypto => "cannot start login: cryptographic failure",
        himmelcloak::Error::InvalidConfiguration(_) => "cannot start login: invalid configuration",
        _ => "cannot start login: engine failure",
    }
}

async fn login(config: Config) -> LoginResult<()> {
    let client = PublicClientApplication::with_config(config)
        .await
        .map_err(|_| "cannot connect to Keycloak")?;

    let (mut flow, mut step) = client
        .initiate_auth_flow(Start::default())
        .await
        .map_err(|error| start_error(&error))?;
    let mut password_submitted = false;

    loop {
        let answer = match step {
            AuthStep::Complete(_) => return Ok(()),
            AuthStep::Failed { .. } => return Err("login failed"),
            AuthStep::Challenge(Challenge::Username | Challenge::Password)
                if password_submitted =>
            {
                flow.cancel();
                return Err("login failed");
            }
            AuthStep::Challenge(Challenge::Username) => {
                let mut username = read_input("Username: ", false)?;
                Answer::Username(std::mem::take(&mut *username))
            }
            AuthStep::Challenge(Challenge::Password) => {
                let mut password = read_input("Password: ", true)?;
                password_submitted = true;
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
    install_interrupt_handler()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "cannot start login runtime")?;

    runtime.block_on(login(config))
}
#[cfg(test)]
mod tests {
    use super::{parse_login_config, start_error};
    use std::path::PathBuf;

    #[test]
    fn start_errors_have_fixed_messages() {
        use himmelcloak::Error;
        for (error, message) in [
            (
                Error::HttpStatus(503),
                "cannot start login: unexpected HTTP status",
            ),
            (
                Error::Transport("reset".into()),
                "cannot start login: transport failure",
            ),
            // Keycloak never reached is a network problem, not an engine fault.
            (
                Error::Unreachable("refused".into()),
                "cannot start login: transport failure",
            ),
            (
                Error::Protocol("page"),
                "cannot start login: protocol failure",
            ),
            (
                Error::UnsupportedFactor,
                "cannot start login: unsupported factor",
            ),
            (Error::Crypto, "cannot start login: cryptographic failure"),
            (
                Error::InvalidConfiguration("realm"),
                "cannot start login: invalid configuration",
            ),
            (Error::Expired, "cannot start login: engine failure"),
        ] {
            assert_eq!(start_error(&error), message);
        }
    }

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
#[cfg(test)]
mod terminal_tests {
    use std::{
        fs::File,
        io::{Read, Write},
        os::fd::{AsRawFd, FromRawFd},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };

    use super::{install_interrupt_handler, read_input};

    const SECRET: &str = "synthetic-terminal-test-password";

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn settings(file: &File) -> libc::termios {
        let mut value = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: value points to writable storage for terminal settings.
        assert_eq!(
            unsafe { libc::tcgetattr(file.as_raw_fd(), value.as_mut_ptr()) },
            0,
            "cannot read test terminal settings"
        );
        // SAFETY: tcgetattr initialized value on success.
        unsafe { value.assume_init() }
    }

    fn terminal_pair() -> (File, File) {
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: descriptor pointers are valid; optional arguments are null.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0,
            "cannot create test terminal"
        );
        // SAFETY: openpty returned two owned, distinct descriptors.
        unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) }
    }

    fn read_available(master: &mut File, output: &mut Vec<u8>) {
        let mut descriptor = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one valid pollfd.
        let ready = unsafe { libc::poll(&mut descriptor, 1, 20) };
        assert!(ready >= 0, "terminal poll failed");

        if ready > 0 && descriptor.revents & libc::POLLIN != 0 {
            let mut buffer = [0_u8; 1024];
            let count = master.read(&mut buffer).expect("read test terminal");
            output.extend_from_slice(&buffer[..count]);
            assert!(output.len() < 65_536, "unexpectedly large test output");
        }
    }

    #[test]
    #[ignore = "subprocess helper used by terminal_input_restores_echo"]
    fn terminal_input_child() {
        let Ok(mode) = std::env::var("HC79_TERMINAL_TEST") else {
            return;
        };

        install_interrupt_handler().expect("install test interrupt handler");
        let result = read_input("Password: ", true);

        match mode.as_str() {
            "success" => {
                let value = result.expect("read synthetic password");
                assert!(value.as_str() == SECRET, "unexpected password input");
            }
            "empty" => {
                assert!(matches!(result, Err("input must not be empty")));
            }
            "eof" => {
                assert!(matches!(result, Err("input ended before login completed")));
            }
            _ => panic!("signal should terminate the helper"),
        }

        println!("TERMINAL_TEST_DONE");
    }

    #[test]
    fn terminal_input_restores_echo() {
        for (mode, signal) in [
            ("success", None),
            ("empty", None),
            ("eof", None),
            ("sigint", Some(libc::SIGINT)),
            ("sigterm", Some(libc::SIGTERM)),
            ("sighup", Some(libc::SIGHUP)),
        ] {
            let (mut master, slave) = terminal_pair();

            // Start with both echo flags enabled so restoration is observable.
            let mut initial = settings(&slave);
            initial.c_lflag |= libc::ECHO | libc::ECHONL;
            // SAFETY: initial contains valid settings for the slave terminal.
            assert_eq!(
                unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &initial) },
                0,
                "initialize test terminal"
            );
            let initial = settings(&slave);

            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "test_login::terminal_tests::terminal_input_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("HC79_TERMINAL_TEST", mode)
                .stdin(Stdio::from(slave.try_clone().unwrap()))
                .stdout(Stdio::from(slave.try_clone().unwrap()))
                .stderr(Stdio::from(slave.try_clone().unwrap()))
                .spawn()
                .expect("start terminal test helper");
            let mut child = ChildGuard(child);
            let mut output = Vec::new();

            let deadline = Instant::now() + Duration::from_secs(10);
            while !output.windows(10).any(|part| part == b"Password: ") {
                assert!(Instant::now() < deadline, "{mode}: prompt timed out");
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "{mode}: helper exited before prompting"
                );
                read_available(&mut master, &mut output);
            }

            let hidden = settings(&slave);
            assert_eq!(
                hidden.c_lflag & (libc::ECHO | libc::ECHONL),
                0,
                "{mode}: password prompt appeared before echo was disabled"
            );

            if let Some(signal) = signal {
                master
                    .write_all(SECRET.as_bytes())
                    .expect("queue partial password without pressing Enter");
                // SAFETY: this is the PID of our running subprocess.
                assert_eq!(
                    unsafe { libc::kill(child.0.id() as libc::pid_t, signal) },
                    0,
                    "signal test helper"
                );
            } else {
                let input = match mode {
                    "success" => format!("{SECRET}\n").into_bytes(),
                    "empty" => b"\n".to_vec(),
                    "eof" => vec![4],
                    _ => unreachable!(),
                };
                master.write_all(&input).expect("send test input");
            }

            let deadline = Instant::now() + Duration::from_secs(10);
            let status = loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                assert!(Instant::now() < deadline, "{mode}: helper timed out");
                read_available(&mut master, &mut output);
            };

            // Drain remaining output while keeping the slave open for inspection.
            for _ in 0..5 {
                read_available(&mut master, &mut output);
            }

            if signal.is_some() {
                assert_eq!(status.code(), Some(130), "{mode}: wrong exit status");
                // The next terminal reader should receive only the new newline.
                master.write_all(b"\n").expect("submit next terminal line");

                let mut descriptor = libc::pollfd {
                    fd: slave.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: descriptor points to one valid pollfd.
                let ready = unsafe { libc::poll(&mut descriptor, 1, 1_000) };
                assert!(
                    ready > 0 && descriptor.revents & libc::POLLIN != 0,
                    "{mode}: next terminal line was not readable"
                );

                let mut buffer = [0_u8; 128];
                let count = (&slave).read(&mut buffer).expect("read next terminal line");
                assert!(
                    &buffer[..count] == b"\n",
                    "{mode}: pending password input survived the interrupt"
                );
            } else {
                assert!(status.success(), "{mode}: helper failed");
                assert!(
                    output
                        .windows(b"TERMINAL_TEST_DONE".len())
                        .any(|part| part == b"TERMINAL_TEST_DONE"),
                    "{mode}: helper did not finish its assertions"
                );
            }

            assert!(
                !output
                    .windows(SECRET.len())
                    .any(|part| part == SECRET.as_bytes()),
                "{mode}: password leaked into terminal output"
            );

            let restored = settings(&slave);
            assert_eq!(
                restored.c_lflag, initial.c_lflag,
                "{mode}: terminal flags were not restored"
            );
        }
    }
}
