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
//! PAM module for native Keycloak login, installed as pam_himmelcloak.so.

pub mod config;
pub mod conversation;

use std::ffi::{c_char, c_int, c_void};

const PAM_AUTH_ERR: c_int = 7;
const PAM_PERM_DENIED: c_int = 6;
const PAM_CRED_ERR: c_int = 17;
const PAM_CONV_ERR: c_int = 19;

/// Deny authentication until the login flow is implemented.
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_authenticate(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_AUTH_ERR
}

/// Deny account access until account checks are implemented.
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_PERM_DENIED
}

/// Fail credential operations until credential handling is implemented.
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_CRED_ERR
}

/// Conversation placeholder; prompting is not implemented yet.
pub fn conversation_stub(_pamh: *mut c_void, _prompt: &str, _echo: bool) -> Result<String, c_int> {
    Err(PAM_CONV_ERR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn authenticate_denies_by_default() {
        for flags in [0, 1, 0x8000, 0x8001] {
            let result = pam_sm_authenticate(ptr::null_mut(), flags, 0, ptr::null());

            assert_eq!(result, 7); // Linux-PAM: PAM_AUTH_ERR
        }
    }

    #[test]
    fn account_access_denies_by_default() {
        for flags in [0, 0x8000] {
            let result = pam_sm_acct_mgmt(ptr::null_mut(), flags, 0, ptr::null());

            assert_eq!(result, 6); // Linux-PAM: PAM_PERM_DENIED
        }
    }

    #[test]
    fn credential_operations_fail_by_default() {
        for flags in [0, 2, 4, 8, 16, 0x8002] {
            let result = pam_sm_setcred(ptr::null_mut(), flags, 0, ptr::null());

            assert_eq!(result, 17); // Linux-PAM: PAM_CRED_ERR
        }
    }

    #[test]
    fn conversation_fails_without_returning_a_response() {
        for echo in [false, true] {
            let result = conversation_stub(ptr::null_mut(), "Password: ", echo);

            assert_eq!(result, Err(19));
        }
    }
}
