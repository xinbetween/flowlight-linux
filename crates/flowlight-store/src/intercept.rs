//! Whether Flowlight terminates connections, and for whom.
//!
//! Off, and off by default, and not the same feature as watching. Everything else in Flowlight reads what an
//! application hands its TLS library and changes nothing; this stands in the middle of a connection, presents a
//! certificate the application has to be persuaded to trust, and can answer a request the server never saw.
//!
//! That is a different bargain, so it is a different switch, with its own scope. Interception applies to the
//! agents it names and to nobody else, and a host nobody has written a mock for is passed through untouched
//! rather than terminated for the sake of it.
//!
//! # Why the scope is agents and not everything
//!
//! Because the failure mode is a broken machine. An application that pins its certificates sees a certificate
//! it does not expect and stops working, and if the scope were "everything" the first symptom would be that
//! the package manager, the browser and the update service all broke at once.

use crate::Result;
use flowlight_text::Language;
use rusqlite::{Connection, OptionalExtension as _, params};

/// Where the proxy listens unless told otherwise.
///
/// Loopback, because the redirect is done by the kernel: nothing has to be reachable from anywhere else, and a
/// terminating proxy is the last thing to put on an address.
pub const DEFAULT_PORT: u16 = 7891;

/// Whether connections are terminated, and whose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intercept {
    /// Whether the feature is on at all.
    pub enabled: bool,
    /// Which port the proxy listens on.
    pub port: u16,
    /// The agents whose connections are redirected.
    ///
    /// Empty means nobody, not everybody. A scope that defaulted to the machine would break the first thing
    /// that pinned a certificate, and the first thing that pins a certificate is usually the package manager.
    pub agents: Vec<String>,
    /// Hosts that are never terminated, whatever else says so.
    ///
    /// Passed through as ciphertext, so nothing can be mocked on them and nothing can go wrong with them.
    pub never: Vec<String>,
}

impl Default for Intercept {
    fn default() -> Self {
        Self::fresh()
    }
}

impl Intercept {
    /// Interception nobody has turned on.
    pub fn fresh() -> Self {
        Self {
            enabled: false,
            port: DEFAULT_PORT,
            agents: Vec::new(),
            never: Vec::new(),
        }
    }

    /// Whether anything is being terminated.
    pub fn running(&self) -> bool {
        self.enabled && !self.agents.is_empty()
    }

    /// Why nothing is being terminated, when nothing is.
    pub fn why_not(&self, language: Language) -> Option<String> {
        if self.running() {
            return None;
        }
        Some(
            language
                .say(if !self.enabled {
                    "intercept.why.off"
                } else {
                    "intercept.why.no_agents"
                })
                .to_owned(),
        )
    }

    /// Whether this host is one that must never be terminated.
    ///
    /// Matched the way a rule's subject is, so `*.example.com` means the subdomains and not the apex.
    pub fn is_spared(&self, host: &str) -> bool {
        self.never
            .iter()
            .any(|pattern| flowlight_rules::Subject::parse(pattern).covers_host(host))
    }

    /// What turning this on would mean, in sentences.
    ///
    /// Longer than the other disclosures in this program, because it is the only feature that changes what an
    /// application sees rather than only watching it.
    pub fn disclose(&self, language: Language) -> Vec<String> {
        let mut said = vec![language.say("intercept.watching").to_owned()];
        said.push(if self.agents.is_empty() {
            language.say("intercept.agents.none").to_owned()
        } else {
            language.fill("intercept.agents", &[("agents", &self.agents.join(", "))])
        });
        said.push(language.say("intercept.authority").to_owned());
        said.push(language.say("intercept.passthrough").to_owned());
        if !self.never.is_empty() {
            said.push(language.fill("intercept.never", &[("hosts", &self.never.join(", "))]));
        }
        said.push(language.say("intercept.off").to_owned());
        said.extend(language.caveat().map(str::to_owned));
        said
    }
}

/// Reads the configuration, filling in the defaults for anything never written.
pub(crate) fn read(connection: &Connection) -> Result<Intercept> {
    let mut intercept = Intercept::fresh();
    let get = |key: &str| -> Result<Option<String>> {
        Ok(connection
            .query_row(
                "SELECT value FROM intercept WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()?)
    };
    if let Some(value) = get("enabled")? {
        intercept.enabled = value == "1";
    }
    if let Some(value) = get("port")?
        && let Ok(port) = value.parse::<u16>()
        && port != 0
    {
        intercept.port = port;
    }
    intercept.agents = list(get("agents")?);
    intercept.never = list(get("never")?);
    Ok(intercept)
}

/// A stored list, which is a comma-separated one because an agent's name has no commas in it.
fn list(value: Option<String>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(|part| part.trim().to_owned())
        .filter(|part| !part.is_empty())
        .collect()
}

/// Writes it.
pub(crate) fn write(connection: &Connection, intercept: &Intercept) -> Result<()> {
    let mut put =
        connection.prepare("INSERT OR REPLACE INTO intercept (key, value) VALUES (?1, ?2)")?;
    put.execute(params![
        "enabled",
        if intercept.enabled { "1" } else { "0" }
    ])?;
    put.execute(params!["port", intercept.port.to_string()])?;
    put.execute(params!["agents", intercept.agents.join(",")])?;
    put.execute(params!["never", intercept.never.join(",")])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Off, and off by default. This is the one feature in the program that changes what an application sees.
    #[test]
    fn nothing_is_intercepted_until_somebody_says_so() {
        let intercept = Intercept::fresh();
        assert!(!intercept.enabled);
        assert!(!intercept.running());
        assert!(
            intercept
                .why_not(Language::English)
                .is_some_and(|why| why.contains("off"))
        );
    }

    /// An empty scope means nobody, not everybody. The other reading would break the package manager first.
    #[test]
    fn an_empty_scope_means_nobody() {
        let intercept = Intercept {
            enabled: true,
            ..Intercept::fresh()
        };
        assert!(!intercept.running());
        assert!(
            intercept
                .why_not(Language::English)
                .is_some_and(|why| why.contains("names no agents"))
        );

        let scoped = Intercept {
            agents: vec!["claude".to_owned()],
            ..intercept
        };
        assert!(scoped.running());
        assert_eq!(scoped.why_not(Language::English), None);
    }

    #[test]
    fn a_spared_host_is_matched_the_way_a_rule_matches_one() {
        let intercept = Intercept {
            never: vec!["*.example.com".to_owned(), "github.com".to_owned()],
            ..Intercept::fresh()
        };
        assert!(intercept.is_spared("a.example.com"));
        assert!(intercept.is_spared("github.com"));
        // A subdomain pattern covers subdomains and not the apex, here as everywhere.
        assert!(!intercept.is_spared("example.com"));
        assert!(!intercept.is_spared("api.anthropic.com"));
    }

    /// The disclosure has to say the thing that will actually go wrong: something that pins its certificates
    /// stops working, and that is correct behaviour rather than a bug.
    #[test]
    fn the_disclosure_says_what_will_break() {
        let said = Intercept {
            enabled: true,
            agents: vec!["claude".to_owned()],
            ..Intercept::fresh()
        }
        .disclose(Language::English)
        .join(" ");
        assert!(said.contains("is not watching"));
        assert!(said.contains("pinned certificate"));
        assert!(said.contains("redirected to a proxy"));
        assert!(said.contains("passed through without being terminated"));
    }
}
