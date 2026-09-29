//! Keeping credentials out of the output.
//!
//! This exists because of something that happened rather than something that was anticipated. The first CI
//! run that read plaintext successfully also read the runner's own traffic, and printed this to the log:
//!
//! ```text
//! PUT /actions-results/…/step-logs-….txt?se=2026-09-29T08%3A31%3A14Z&sig=5gEsMksh%2BjBO0Wb8…%3D&…
//! ```
//!
//! That `sig` is a live Azure shared-access signature: anyone reading the log could write to that blob until
//! it expired. Nothing was doing anything wrong — a URL is not a secret, except when it is, and a signed URL
//! is *entirely* a secret.
//!
//! A tool that watches traffic in order to make it safer cannot be a new way for credentials to escape. So
//! the request target is redacted before it is printed, stored or exported, and it is redacted here — in the
//! shared crate, on the way in — rather than at each of the places it is eventually shown.
//!
//! # Two rules, and why neither is enough alone
//!
//! **By name.** `sig`, `token`, `api_key` and their relatives are credentials whatever they contain. This
//! catches the common case exactly, and catches nothing it has not been told about.
//!
//! **By shape.** A long mixed-case value with digits in it is not a word, a date, an identifier or a page
//! number — it is an encoded secret. This catches the parameter nobody added to the list, which is the one
//! that matters, at the cost of occasionally hiding something that was not a secret. That trade is the right
//! way round: a hidden value can be recovered by looking at the traffic, and a published one cannot be
//! unpublished.

use alloc::borrow::ToOwned as _;
use alloc::string::String;

/// What replaces a redacted value. Short, and obviously not a value.
const REDACTED: &str = "…";

/// Query parameter names that are credentials regardless of what is in them.
///
/// Compared case-insensitively and after any `x-` or `amz-` style prefix, so `X-Amz-Signature` matches
/// `signature`.
const SECRET_NAMES: &[&str] = &[
    "sig",
    "signature",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "auth",
    "authorization",
    "key",
    "apikey",
    "api_key",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "pwd",
    "session",
    "sessionid",
    "sid",
    "credential",
    "security_token",
    "sas",
];

/// The length at which an opaque value stops being plausibly a word.
const OPAQUE_LENGTH: usize = 32;

/// A request target with its credentials removed.
///
/// The path is left alone — it is what makes the line useful, and a path is not a credential in any API
/// worth watching. Only query values are touched, and only the ones that are credentials by name or by
/// shape.
pub fn redact_target(target: &str) -> String {
    let Some((path, query)) = target.split_once('?') else {
        return target.to_owned();
    };
    let mut out = String::with_capacity(target.len());
    out.push_str(path);
    out.push('?');
    for (index, pair) in query.split('&').enumerate() {
        if index > 0 {
            out.push('&');
        }
        match pair.split_once('=') {
            Some((name, value)) if is_secret(name) || is_opaque(value) => {
                out.push_str(name);
                out.push('=');
                out.push_str(REDACTED);
            }
            _ => out.push_str(pair),
        }
    }
    out
}

/// Whether a parameter name is one of the known credentials.
fn is_secret(name: &str) -> bool {
    let name = name.trim();
    if SECRET_NAMES.iter().any(|s| name.eq_ignore_ascii_case(s)) {
        return true;
    }
    // `X-Amz-Signature`, `x-goog-signature`, `amz-security-token`: a vendor prefix on a name we know.
    name.rsplit('-')
        .next()
        .is_some_and(|last| SECRET_NAMES.iter().any(|s| last.eq_ignore_ascii_case(s)))
}

/// Whether a value is long and encoded enough that it cannot be anything but a secret.
///
/// Deliberately narrow. A UUID is lower-case hex with dashes and stays visible, because resource identifiers
/// are most of what makes a request line worth reading. A date, a page number and a model name all stay
/// visible for the same reason.
fn is_opaque(value: &str) -> bool {
    if value.len() < OPAQUE_LENGTH {
        return false;
    }
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    for c in value.chars() {
        match c {
            'A'..='Z' => has_upper = true,
            'a'..='z' => has_lower = true,
            '0'..='9' => has_digit = true,
            // The rest of base64url, and the `%` of a percent-encoded `+` or `=`.
            '+' | '/' | '=' | '_' | '-' | '%' | '.' | '~' => {}
            // Anything else — a space, a comma, a colon, a letter with an accent — is prose or a list, not
            // an encoded blob.
            _ => return false,
        }
    }
    has_upper && has_lower && has_digit
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact URL that caused this module to exist, from the CI log that printed it.
    #[test]
    fn the_azure_signature_that_started_this_is_removed() {
        let target = "/actions-results/1e747f7f/logs/step-logs.txt?se=2026-09-29T08%3A31%3A14Z\
                      &sig=5gEsMksh%2BjBO0Wb8KDHnBhSK3nOgcxyPd%2BkCB7Ku5kI%3D&sp=cw&sv=2025-11-05";
        let redacted = redact_target(target);
        assert!(!redacted.contains("5gEsMksh"), "{redacted}");
        assert!(redacted.contains("sig=…"), "{redacted}");
        // The rest of the URL is what makes the line worth printing and is not secret.
        assert!(redacted.starts_with("/actions-results/1e747f7f/logs/step-logs.txt?"));
        assert!(redacted.contains("sp=cw"), "{redacted}");
        assert!(redacted.contains("sv=2025-11-05"), "{redacted}");
    }

    #[test]
    fn a_path_without_a_query_is_untouched() {
        assert_eq!(redact_target("/v1/messages"), "/v1/messages");
        assert_eq!(redact_target("/"), "/");
    }

    #[test]
    fn credentials_are_removed_by_name_however_short_they_are() {
        for name in ["token", "api_key", "APIKEY", "password", "X-Amz-Signature"] {
            let redacted = redact_target(&alloc::format!("/x?{name}=abc"));
            assert!(redacted.ends_with("=…"), "{name}: {redacted}");
        }
    }

    /// The parameter nobody thought to add to the list. This is the rule that earns its keep.
    #[test]
    fn a_long_encoded_value_is_removed_whatever_it_is_called() {
        let target = "/x?wibble=MDAwMTExMjIyMzMzNDQ0NTU1Njc4OUFCQ0RFRg";
        assert_eq!(redact_target(target), "/x?wibble=…");
    }

    /// The other half of the trade. A request line whose identifiers are all hidden is not worth printing,
    /// so the shape rule has to leave the things that make it readable alone.
    #[test]
    fn the_parts_of_a_url_that_make_it_useful_survive() {
        for target in [
            "/v1/messages?model=claude-opus-5&max_tokens=1024",
            "/repos/xinbetween/flowlight/issues?state=open&per_page=100",
            // A UUID: lower-case hex and dashes, no upper case. The commonest resource identifier there is.
            "/jobs/d993ec31-40ba-5a83-8577-acfe67c43797/logs",
            "/search?q=how+do+i+redact+a+url&lang=en",
            "/x?since=2026-09-29T08%3A31%3A14Z",
        ] {
            assert_eq!(redact_target(target), target, "{target}");
        }
    }

    /// A query with nothing that looks like a pair is passed through rather than mangled.
    #[test]
    fn a_query_that_is_not_pairs_is_left_as_it_is() {
        assert_eq!(redact_target("/x?flag"), "/x?flag");
        assert_eq!(redact_target("/x?"), "/x?");
        assert_eq!(redact_target("/x?a&b=1"), "/x?a&b=1");
    }

    /// Nothing here may panic on a target chosen by whoever is on the other end of the connection.
    #[test]
    fn nothing_in_a_hostile_target_causes_a_panic() {
        for target in ["?", "??", "&&&", "=", "/x?=", "/x?a=", "/x?=b", "…?…=…"] {
            let _ = redact_target(target);
        }
    }
}
