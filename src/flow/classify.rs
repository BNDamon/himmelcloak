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
//! Theme-independent page/authenticator classification.
//!
//! Classify each Keycloak page by CORE-defined form field names (theme cannot change these),
//! never by visible/localized text:
//!   password        -> input name="password"
//!   TOTP/OTP        -> input name="otp"
//!   WebAuthn        -> inputs clientDataJSON / authenticatorData / signature (+ options script)
//!   recovery codes  -> input name="recoveryCodeInput"
//!   required action -> kc_action marker / action page
//! Only a Keycloak MAJOR-version core change should break this, caught by the CI version matrix.
//!
//! The login and one-time-code pages are classified today. A page is matched only when every
//! named field in its single form is on that page's allow-list; anything else is `Unknown`, and
//! the flow denies it rather than guess.
use html5gum::{DefaultEmitter, HtmlString, StartTag, Token, Tokenizer};

use crate::flow::OtpDevice;

/// Element ID prefix both themes give each OTP device: the radio input in `base`, the tile in
/// `keycloak.v2`.
const DEVICE_ID_PREFIX: &str = "kc-otp-credential-";
const LOGIN_FIELDS: &[&str] = &[
    "username",
    "password",
    "credentialId",
    "rememberMe",
    "login",
];
const OTP_FIELDS: &[&str] = &["otp", "selectedCredentialId", "login"];

/// What a Keycloak page asks for, judged only by its form-field names.
pub(crate) enum PageKind {
    /// `login.ftl`: username and password posted together.
    UsernamePassword,
    /// `login-otp.ftl`. `devices` is empty unless Keycloak offers a choice of devices.
    OneTimeCode { devices: Vec<OtpDevice> },
    /// Any other page, or a known page with unexpected fields. The flow denies it.
    Unknown,
}

/// Classify a fetched page body. Never fails: anything unrecognised is `Unknown`.
///
/// The tokenizer copies attribute values, including the form action's `session_code`, without
/// zeroizing them; those copies live only until this call returns.
pub(crate) fn classify(body: &[u8]) -> PageKind {
    let Ok(html) = std::str::from_utf8(body) else {
        return PageKind::Unknown;
    };
    Scan::run(html).kind().unwrap_or(PageKind::Unknown)
}

/// A named form control a browser would submit.
struct Control {
    name: String,
    kind: String,
    value: String,
}

/// An element whose ID is `kc-otp-credential-N`.
struct Tile {
    index: usize,
    credential: Option<String>,
    /// The `base` radio input; its label is a separate `<label for=...>`.
    is_input: bool,
    text: String,
}

enum Target {
    Label(String),
    Tile(usize),
}

/// Text being collected until the element that started it closes.
struct Capture {
    target: Target,
    tag: Vec<u8>,
    depth: usize,
    text: String,
}

#[derive(Default)]
struct Scan {
    forms: usize,
    in_form: bool,
    controls: Vec<Control>,
    labels: Vec<(String, String)>,
    tiles: Vec<Tile>,
    capture: Option<Capture>,
    /// How many `<template>` elements enclose the current position. Their contents are inert:
    /// never shown or submitted, so nothing inside them counts.
    templates: usize,
    /// A structure a real Keycloak page never has: nested forms, or controls that submit
    /// outside their form.
    suspicious: bool,
}

impl Scan {
    fn run(html: &str) -> Self {
        let mut emitter = DefaultEmitter::default();
        // Treat <script>, <style>, and similar contents as text, as a browser does, so markup
        // inside JavaScript is never mistaken for a form field.
        emitter.naively_switch_states(true);
        let mut scan = Self::default();
        for token in Tokenizer::new_with_emitter(html, emitter) {
            let Ok(token) = token;
            match token {
                Token::StartTag(tag) => scan.start(&tag),
                Token::EndTag(tag) => scan.end(&tag.name),
                Token::String(text) if scan.templates == 0 => {
                    if let Some(capture) = &mut scan.capture {
                        capture.text.push_str(&String::from_utf8_lossy(&text.value));
                    }
                }
                _ => {}
            }
        }
        scan
    }

    fn start(&mut self, tag: &StartTag<()>) {
        let name = tag.name.as_slice();
        if name == b"template" && !tag.self_closing {
            self.templates += 1;
        }
        if self.templates > 0 {
            return;
        }
        if let Some(capture) = &mut self.capture {
            if capture.tag == name && !tag.self_closing {
                capture.depth += 1;
            }
        }
        match name {
            b"form" if self.in_form => self.suspicious = true,
            b"form" => {
                self.in_form = true;
                self.forms += 1;
            }
            b"input" | b"select" | b"textarea" | b"button" => self.control(tag),
            b"label" => {
                if let Some(target) = attribute(tag, "for") {
                    self.begin(Target::Label(target), name, tag.self_closing);
                }
            }
            _ => {}
        }
        if let Some(index) = attribute(tag, "id")
            .and_then(|id| id.strip_prefix(DEVICE_ID_PREFIX)?.parse::<usize>().ok())
        {
            let is_input = name == b"input";
            let credential = if is_input {
                attribute(tag, "value")
            } else {
                attribute(tag, "onclick").and_then(|onclick| toggle_credential(&onclick, index))
            };
            self.tiles.push(Tile {
                index,
                credential,
                is_input,
                text: String::new(),
            });
            if !is_input {
                self.begin(Target::Tile(self.tiles.len() - 1), name, tag.self_closing);
            }
        }
    }

    fn control(&mut self, tag: &StartTag<()>) {
        // `form` and `formaction` would send a control somewhere other than its form.
        if attribute(tag, "form").is_some() || attribute(tag, "formaction").is_some() {
            self.suspicious = true;
        }
        let Some(name) = attribute(tag, "name").filter(|name| !name.is_empty()) else {
            return;
        };
        if !self.in_form {
            self.suspicious = true;
            return;
        }
        let default_kind = if tag.name.as_slice() == b"button" {
            "submit"
        } else {
            "text"
        };
        self.controls.push(Control {
            name,
            kind: attribute(tag, "type")
                .map(|kind| kind.to_ascii_lowercase())
                .unwrap_or_else(|| default_kind.to_owned()),
            value: attribute(tag, "value").unwrap_or_default(),
        });
    }

    fn begin(&mut self, target: Target, tag: &[u8], self_closing: bool) {
        if self.capture.is_none() && !self_closing {
            self.capture = Some(Capture {
                target,
                tag: tag.to_vec(),
                depth: 1,
                text: String::new(),
            });
        }
    }

    fn end(&mut self, name: &HtmlString) {
        if self.templates > 0 {
            if name.as_slice() == b"template" {
                self.templates -= 1;
            }
            return;
        }
        if name.as_slice() == b"form" {
            self.in_form = false;
        }
        match self.capture.take() {
            Some(mut capture) if capture.tag == name.as_slice() => {
                capture.depth -= 1;
                if capture.depth > 0 {
                    self.capture = Some(capture);
                    return;
                }
                match capture.target {
                    Target::Label(target) => self.labels.push((target, capture.text)),
                    Target::Tile(index) => self.tiles[index].text = capture.text,
                }
            }
            other => self.capture = other,
        }
    }

    fn kind(&self) -> Option<PageKind> {
        // Every Keycloak login page has exactly one form; a second one, even empty, is not a
        // page we know.
        if self.suspicious || self.forms != 1 {
            return None;
        }
        if self.has("username") && self.has("password") {
            let login = self.only(LOGIN_FIELDS) && self.unique() && self.tiles.is_empty();
            return login.then_some(PageKind::UsernamePassword);
        }
        if self.has("otp") && !self.has("password") && self.only(OTP_FIELDS) && self.unique() {
            return self
                .devices()
                .map(|devices| PageKind::OneTimeCode { devices });
        }
        None
    }

    fn has(&self, name: &str) -> bool {
        self.controls.iter().any(|control| control.name == name)
    }

    fn only(&self, allowed: &[&str]) -> bool {
        self.controls
            .iter()
            .all(|control| allowed.contains(&control.name.as_str()))
    }

    /// Each field appears once, except the device radios, which share one name. Any other
    /// radio that repeats a name is a duplicate like any other field.
    fn unique(&self) -> bool {
        self.controls.iter().enumerate().all(|(i, control)| {
            (control.kind == "radio" && control.name == "selectedCredentialId")
                || !self.controls[..i]
                    .iter()
                    .any(|earlier| earlier.name == control.name)
        })
    }

    /// The device choice, which the themes mark up differently: `base` posts the chosen radio's
    /// value; `keycloak.v2` shows tiles and posts one hidden field the page's script updates.
    fn devices(&self) -> Option<Vec<OtpDevice>> {
        let mut tiles: Vec<&Tile> = self.tiles.iter().collect();
        tiles.sort_by_key(|tile| tile.index);
        if tiles.iter().enumerate().any(|(i, tile)| tile.index != i) {
            return None;
        }
        let devices = tiles
            .iter()
            .map(|tile| {
                let id = tile.credential.clone().filter(|id| !id.is_empty())?;
                let text = if tile.is_input {
                    let element = format!("{DEVICE_ID_PREFIX}{}", tile.index);
                    &self.labels.iter().find(|(target, _)| *target == element)?.1
                } else {
                    &tile.text
                };
                let label = clean_label(text);
                (!label.is_empty()).then(|| OtpDevice::new(id, label))
            })
            .collect::<Option<Vec<_>>>()?;
        let ids: Vec<&str> = devices.iter().map(|device| device.id.as_str()).collect();
        if ids.iter().enumerate().any(|(i, id)| ids[..i].contains(id)) {
            return None;
        }

        let selected: Vec<&Control> = self
            .controls
            .iter()
            .filter(|control| control.name == "selectedCredentialId")
            .collect();
        let radios: Vec<&str> = selected
            .iter()
            .filter(|control| control.kind == "radio")
            .map(|control| control.value.as_str())
            .collect();
        let hidden: Vec<&str> = selected
            .iter()
            .filter(|control| control.kind == "hidden")
            .map(|control| control.value.as_str())
            .collect();
        if radios.len() + hidden.len() != selected.len() {
            return None;
        }
        let consistent = match (radios.is_empty(), hidden.as_slice()) {
            // base: one radio per device, each carrying that device's ID.
            (false, []) => radios == ids && tiles.iter().all(|tile| tile.is_input),
            // keycloak.v2: one hidden field holding the default device, plus tiles if several.
            (true, [default]) => {
                ids.is_empty() || (ids.contains(default) && tiles.iter().all(|tile| !tile.is_input))
            }
            // A single device needs no choice.
            (true, []) => ids.is_empty(),
            _ => false,
        };
        consistent.then_some(devices)
    }
}

fn attribute(tag: &StartTag<()>, name: &str) -> Option<String> {
    tag.attributes
        .iter()
        .find(|(key, _)| key.as_slice() == name.as_bytes())
        .map(|(_, value)| String::from_utf8_lossy(&value.value).into_owned())
}

/// `keycloak.v2` keeps a tile's credential ID only in `onclick="toggleOTP(<index>, '<id>')"`.
fn toggle_credential(onclick: &str, index: usize) -> Option<String> {
    let arguments = onclick
        .trim()
        .trim_end_matches(';')
        .strip_prefix("toggleOTP(")?
        .strip_suffix(')')?;
    let (position, credential) = arguments.split_once(',')?;
    if position.trim().parse::<usize>().ok()? != index {
        return None;
    }
    let credential = credential.trim();
    let quote = credential
        .chars()
        .next()
        .filter(|c| matches!(c, '\'' | '"'))?;
    let id = credential.strip_prefix(quote)?.strip_suffix(quote)?;
    (!id.is_empty() && !id.contains(['\'', '"', '\\'])).then(|| id.to_owned())
}

/// Device labels come from the page and are shown in a terminal: drop control and
/// bidirectional-override characters, and collapse whitespace.
fn clean_label(text: &str) -> String {
    let kept: String = text
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
        })
        .collect();
    kept.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::{classify, toggle_credential, PageKind};

    const BASE_LOGIN: &str = include_str!("../../tests/fixtures/keycloak/base/login.html");
    const BASE_OTP: &str = include_str!("../../tests/fixtures/keycloak/base/login-otp.html");
    const BASE_DEVICES: &str =
        include_str!("../../tests/fixtures/keycloak/base/login-otp-devices.html");
    const V2_LOGIN: &str = include_str!("../../tests/fixtures/keycloak/keycloak.v2/login.html");
    const V2_OTP: &str = include_str!("../../tests/fixtures/keycloak/keycloak.v2/login-otp.html");
    const V2_DEVICES: &str =
        include_str!("../../tests/fixtures/keycloak/keycloak.v2/login-otp-devices.html");

    /// carol's two devices from the charter's fixture realm (Table 23).
    const TOTP_DEVICE: &str = "00000000-0000-4000-8000-000000000001";
    const HOTP_DEVICE: &str = "00000000-0000-4000-8000-000000000002";
    const TOTP_LABEL: &str = "Authenticator app";

    fn kind(html: &str) -> PageKind {
        classify(html.as_bytes())
    }

    /// The device list, or `None` when the page is not a one-time-code page.
    fn devices(html: &str) -> Option<Vec<(String, String)>> {
        match kind(html) {
            PageKind::OneTimeCode { devices } => Some(
                devices
                    .into_iter()
                    .map(|device| (device.id, device.label))
                    .collect(),
            ),
            _ => None,
        }
    }

    fn is_unknown(html: &str) -> bool {
        matches!(kind(html), PageKind::Unknown)
    }

    /// Insert `extra` just before the page's first `</form>`.
    fn with_in_form(page: &str, extra: &str) -> String {
        page.replacen("</form>", &format!("{extra}</form>"), 1)
    }

    #[test]
    fn login_pages_in_both_themes() {
        for page in [BASE_LOGIN, V2_LOGIN] {
            assert!(matches!(kind(page), PageKind::UsernamePassword));
            assert_eq!(devices(page), None);
        }
    }

    #[test]
    fn single_device_code_pages_in_both_themes() {
        for page in [BASE_OTP, V2_OTP] {
            assert_eq!(devices(page), Some(vec![]));
        }
    }

    #[test]
    fn device_choices_in_both_themes() {
        let expected = vec![
            (TOTP_DEVICE.to_owned(), TOTP_LABEL.to_owned()),
            (HOTP_DEVICE.to_owned(), "Hardware token".to_owned()),
        ];
        assert_eq!(devices(BASE_DEVICES), Some(expected.clone()));
        assert_eq!(devices(V2_DEVICES), Some(expected));
    }

    #[test]
    fn unexpected_fields_make_a_page_unknown() {
        assert!(is_unknown(&with_in_form(
            BASE_LOGIN,
            r#"<input name="email">"#
        )));
        assert!(is_unknown(&with_in_form(V2_OTP, r#"<input name="email">"#)));
        assert!(is_unknown(&with_in_form(
            BASE_OTP,
            r#"<input type="password" name="password">"#
        )));
        assert!(is_unknown(&with_in_form(
            V2_LOGIN,
            r#"<input name="username">"#
        )));
    }

    #[test]
    fn only_device_radios_may_repeat() {
        assert!(is_unknown(&with_in_form(
            BASE_LOGIN,
            r#"<input type="radio" name="username" value="mallory">"#
        )));
        assert!(is_unknown(&with_in_form(
            V2_OTP,
            r#"<input type="radio" name="otp" value="000000">"#
        )));
    }

    #[test]
    fn pages_without_a_single_form_are_unknown() {
        for page in [
            "",
            "<html><body><p>Hello</p></body></html>",
            r#"<input name="username"><input name="password">"#,
        ] {
            assert!(is_unknown(page), "{page:?}");
        }
        let second_form = BASE_LOGIN.replace(
            "</body>",
            r#"<form action="/other"><input name="otp"></form></body>"#,
        );
        assert!(is_unknown(&second_form));
        let empty_second_form =
            BASE_LOGIN.replace("</body>", r#"<form action="/other"></form></body>"#);
        assert!(is_unknown(&empty_second_form));
        assert!(is_unknown(&with_in_form(
            BASE_LOGIN,
            "<form><input name=\"otp\">"
        )));
        assert!(matches!(classify(&[0xff, 0xfe]), PageKind::Unknown));
    }

    #[test]
    fn controls_that_submit_elsewhere_make_a_page_unknown() {
        assert!(is_unknown(&BASE_LOGIN.replace(
            "</body>",
            r#"<input name="password" form="kc-form-login"></body>"#
        )));
        assert!(is_unknown(&with_in_form(
            V2_LOGIN,
            r#"<button formaction="https://evil.example/">Go</button>"#
        )));
    }

    #[test]
    fn markup_inside_scripts_is_not_a_field() {
        let page = with_in_form(
            BASE_LOGIN,
            r#"<script>document.write('<input name="email">')</script>"#,
        );
        assert!(matches!(kind(&page), PageKind::UsernamePassword));
    }

    #[test]
    fn markup_inside_templates_is_inert() {
        // A form whose only login fields sit in a template has no live fields.
        assert!(is_unknown(
            r#"<form><template><input name="username"><input type="password" name="password"></template></form>"#
        ));
        // Inert fields, forms, and nested templates do not change a real page.
        let page = with_in_form(
            BASE_LOGIN,
            r#"<template><input name="email"><template><form></form></template><input name="otp"></template>"#,
        );
        assert!(matches!(kind(&page), PageKind::UsernamePassword));
    }

    #[test]
    fn inconsistent_device_lists_are_unknown() {
        assert!(is_unknown(&V2_DEVICES.replace(
            r#"name="selectedCredentialId" value="00000000-0000-4000-8000-000000000001""#,
            r#"name="selectedCredentialId" value="00000000-0000-4000-8000-000000000009""#
        )));
        assert!(is_unknown(&V2_DEVICES.replace(
            "toggleOTP(1, '00000000-0000-4000-8000-000000000002')",
            "toggleOTP(1, '00000000-0000-4000-8000-000000000001')"
        )));
        assert!(is_unknown(&BASE_DEVICES.replace(
            r#"<label for="kc-otp-credential-1""#,
            r#"<label for="something-else""#
        )));
        assert!(is_unknown(&V2_OTP.replace(
            r#"type="hidden" name="selectedCredentialId""#,
            r#"type="text" name="selectedCredentialId""#
        )));
    }

    #[test]
    fn device_tiles_must_agree_with_the_posted_choice() {
        // keycloak.v2 tiles with no hidden field would leave no way to post the choice.
        assert!(is_unknown(&V2_DEVICES.replace(
            r#"<input id="selectedCredentialId" type="hidden" name="selectedCredentialId" value="00000000-0000-4000-8000-000000000001">"#,
            ""
        )));
        // A base radio with no matching device tile.
        assert!(is_unknown(&with_in_form(
            BASE_DEVICES,
            r#"<input type="radio" name="selectedCredentialId" value="extra">"#
        )));
        // Radios and a hidden choice together.
        assert!(is_unknown(&BASE_DEVICES.replacen(
            r#"<input id="kc-otp-credential-0""#,
            r#"<input type="hidden" name="selectedCredentialId" value="00000000-0000-4000-8000-000000000001"><input id="kc-otp-credential-0""#,
            1
        )));
        // Device numbering with a gap.
        assert!(is_unknown(&V2_DEVICES.replace(
            r#"id="kc-otp-credential-1""#,
            r#"id="kc-otp-credential-5""#
        )));
        // Device markup on the login page.
        assert!(is_unknown(&with_in_form(
            BASE_LOGIN,
            r#"<div id="kc-otp-credential-0" onclick="toggleOTP(0, 'x')">Phone</div>"#
        )));
    }

    #[test]
    fn device_labels_survive_nested_markup() {
        let title = format!(r#"<span class="pf-v5-c-tile__title">{TOTP_LABEL}</span>"#);
        assert!(V2_DEVICES.contains(&title));
        let page = V2_DEVICES.replace(&title, &format!("<div><div>{title}</div></div>"));
        assert_eq!(devices(&page).unwrap()[0].1, TOTP_LABEL);
    }

    #[test]
    fn forms_with_neither_login_nor_code_fields_are_unknown() {
        for page in [
            r#"<form><input name="username"></form>"#,
            r#"<form><input name="password"></form>"#,
            r#"<form><button name="login">Sign in</button></form>"#,
        ] {
            assert!(is_unknown(page), "{page}");
        }
    }

    #[test]
    fn toggle_credential_reads_only_the_expected_call() {
        assert_eq!(
            toggle_credential("toggleOTP(0, 'id-a')", 0).as_deref(),
            Some("id-a")
        );
        assert_eq!(
            toggle_credential(" toggleOTP(2,\"id-b\"); ", 2).as_deref(),
            Some("id-b")
        );
        for (onclick, index) in [
            ("toggleOTP(1, 'id-a')", 0),
            ("toggleOTP(0, id-a)", 0),
            ("toggleOTP(0, 'id-a\")", 0),
            ("toggleOTP(0, '')", 0),
            ("toggleOTP(0, 'a\\'b')", 0),
            ("toggleOTP(0)", 0),
            ("steal(0, 'id-a')", 0),
            ("toggleOTP(0, 'id-a'); steal()", 0),
        ] {
            assert_eq!(toggle_credential(onclick, index), None, "{onclick}");
        }
    }

    #[test]
    fn device_labels_lose_terminal_control_characters() {
        let title = format!(">{TOTP_LABEL}<");
        assert!(V2_DEVICES.contains(&title));
        let page = V2_DEVICES.replace(&title, ">Pho\u{1b}[31mne\u{202e}\n  1<");
        assert_eq!(devices(&page).unwrap()[0].1, "Pho[31mne 1");
        let blank = V2_DEVICES.replace(&title, ">\u{7}\u{200b}<");
        assert!(is_unknown(&blank));
    }
}
