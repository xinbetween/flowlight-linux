//! Which model answers questions about this machine, and what that means.
//!
//! There is no model in this program. macOS has one the operating system provides; Linux does not, so the
//! feature is off until somebody names an endpoint — a server on this machine, or a provider they have an
//! account with. There are no bundled weights and no default that quietly points at somebody's API.
//!
//! # Why the settings are here and the sending is not
//!
//! The same split as [`crate::export`]: what is allowed lives next to what is stored, so that the rule and
//! the record cannot disagree. Which endpoints are safe to send a key to is a policy question, and it is
//! answered here rather than in the code that opens the socket, where it would be one `if` away from being
//! forgotten.
//!
//! # Why the key is not in this database
//!
//! Because a database gets copied. This one holds a history somebody may reasonably hand to a colleague or
//! attach to a bug report, and a key inside it travels with it. The key lives in its own file, mode 600, and
//! is read at the moment it is needed.

use crate::Result;
use flowlight_text::Language;
use rusqlite::{Connection, OptionalExtension as _, params};
use std::fmt;

/// Where a model server on this machine usually is.
///
/// Ollama's default port and the path every OpenAI-compatible server serves. Offered as a default only for
/// the local kind, because filling in a default for a hosted provider is how a tool starts sending things
/// nobody chose to send.
pub const LOCAL_ENDPOINT: &str = "http://127.0.0.1:11434/v1/chat/completions";

/// Who answers.
///
/// Ordered so that the one that sends nothing anywhere comes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// A model server already running on this machine or this network: Ollama, LM Studio, llama.cpp.
    ///
    /// Nothing leaves. Flowlight still records the connection to it, attributed to `flowlightd`, because a
    /// tool that hides its own traffic has no business showing anybody else's.
    Local,
    /// Anything that speaks the OpenAI chat-completions shape, somewhere else.
    Compatible,
    /// Anthropic's messages API.
    Anthropic,
    /// Google's Gemini API.
    Gemini,
}

/// Every kind, in the order they are offered.
pub const EVERY_KIND: &[Kind] = &[Kind::Local, Kind::Compatible, Kind::Anthropic, Kind::Gemini];

impl Kind {
    /// The name this is written down and configured under.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Compatible => "compatible",
            Self::Anthropic => "anthropic",
            Self::Gemini => "gemini",
        }
    }

    /// How this reads in a sentence, in the language somebody is reading.
    pub fn described(self, language: Language) -> &'static str {
        language.say(match self {
            Self::Local => "ask.kind.local",
            Self::Compatible => "ask.kind.compatible",
            Self::Anthropic => "ask.kind.anthropic",
            Self::Gemini => "ask.kind.gemini",
        })
    }

    /// Reads one back, or nothing if it is not one.
    pub fn parse(text: &str) -> Option<Self> {
        EVERY_KIND
            .iter()
            .copied()
            .find(|kind| kind.as_str() == text.trim().to_lowercase())
    }

    /// Whether choosing this means a question about this machine leaves it.
    pub fn sends_off_the_machine(self) -> bool {
        !matches!(self, Self::Local)
    }

    /// Whether it needs a key.
    pub fn needs_key(self) -> bool {
        self.sends_off_the_machine()
    }

    /// The endpoint to start from, where there is an obvious one.
    pub fn suggested_endpoint(self) -> Option<&'static str> {
        match self {
            Self::Local => Some(LOCAL_ENDPOINT),
            Self::Anthropic => Some("https://api.anthropic.com/v1/messages"),
            // Gemini puts the model in the path, so what is configured is the base.
            Self::Gemini => Some("https://generativelanguage.googleapis.com/v1beta/models"),
            // Deliberately none. "Compatible" means somebody's own server, and guessing at its address would
            // be guessing at whose.
            Self::Compatible => None,
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(self.as_str())
    }
}

/// Which model answers, and where it is.
///
/// No key. A key is a secret and lives in its own file; this is the part that is safe to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    /// Whether the feature is on at all.
    pub enabled: bool,
    /// Which sort of provider.
    pub kind: Kind,
    /// Where it is.
    pub endpoint: Option<String>,
    /// Which model to name in the request.
    pub model: Option<String>,
}

impl Default for Ask {
    fn default() -> Self {
        Self::fresh()
    }
}

impl Ask {
    /// An Ask nobody has configured: off, and pointing nowhere.
    pub fn fresh() -> Self {
        Self {
            enabled: false,
            kind: Kind::Local,
            endpoint: None,
            model: None,
        }
    }

    /// Whether a question could be asked right now, given whether a key is on file.
    ///
    /// The key is passed in rather than read here, because reading it is a file operation with its own
    /// failures and this is a predicate.
    pub fn ready(&self, key_on_file: bool) -> bool {
        self.enabled
            && self
                .endpoint
                .as_deref()
                .is_some_and(|endpoint| Safety::of(endpoint, self.kind) == Safety::Fine)
            && self.model.is_some()
            && (!self.kind.needs_key() || key_on_file)
    }

    /// Why a question cannot be asked, when it cannot.
    pub fn why_not(&self, key_on_file: bool, language: Language) -> Option<String> {
        if self.ready(key_on_file) {
            return None;
        }
        Some(if !self.enabled {
            language.say("ask.why.off").to_owned()
        } else if self.endpoint.is_none() {
            language.say("ask.why.no_endpoint").to_owned()
        } else if self.model.is_none() {
            language.say("ask.why.no_model").to_owned()
        } else if let Some(endpoint) = self.endpoint.as_deref() {
            match Safety::of(endpoint, self.kind) {
                Safety::Fine => {
                    language.fill("ask.why.no_key", &[("kind", self.kind.described(language))])
                }
                other => other.describe(endpoint, language),
            }
        } else {
            language.say("ask.why.unconfigured").to_owned()
        })
    }

    /// What asking a question would mean, in sentences.
    ///
    /// Said before the first question rather than in a manual. For a local server it is short, because the
    /// answer is that nothing leaves; for anything else it names the host, because that is the fact.
    pub fn disclose(&self, language: Language) -> Vec<String> {
        let mut said = Vec::new();
        let Some(endpoint) = self.endpoint.as_deref() else {
            said.push(language.say("ask.none").to_owned());
            return said;
        };
        let values = [("endpoint", endpoint)];
        said.push(language.fill(
            if self.kind.sends_off_the_machine() {
                "ask.remote"
            } else {
                "ask.local"
            },
            &values,
        ));
        said.push(language.say("ask.sent").to_owned());
        said.push(language.say("ask.queries").to_owned());
        if self.kind.sends_off_the_machine() {
            said.push(language.say("ask.recorded").to_owned());
        }
        said.extend(language.caveat().map(str::to_owned));
        said
    }
}

/// Whether an endpoint is one a key and a question may be sent to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Safety {
    /// It may.
    Fine,
    /// Not a URL at all.
    NotAUrl,
    /// Plain HTTP to somewhere that is not this machine or a private address.
    ClearOverTheInternet,
    /// A scheme that is neither http nor https.
    WrongScheme,
}

impl Safety {
    /// Why an endpoint was refused, as a sentence.
    pub fn describe(self, endpoint: &str, language: Language) -> String {
        language.fill(
            match self {
                Self::Fine => "ask.safety.fine",
                Self::NotAUrl => "ask.safety.not_a_url",
                Self::WrongScheme => "ask.safety.wrong_scheme",
                Self::ClearOverTheInternet => "ask.safety.clear",
            },
            &[("endpoint", endpoint)],
        )
    }

    /// Whether this endpoint may be sent to.
    ///
    /// HTTPS anywhere. Plain HTTP only where the traffic cannot leave the machine or the local network —
    /// which is the whole point of the local kind, and the one exception worth keeping.
    pub fn of(endpoint: &str, _kind: Kind) -> Self {
        let endpoint = endpoint.trim();
        if let Some(rest) = endpoint.strip_prefix("https://") {
            return if rest.is_empty() {
                Self::NotAUrl
            } else {
                Self::Fine
            };
        }
        let Some(rest) = endpoint.strip_prefix("http://") else {
            return if endpoint.contains("://") {
                Self::WrongScheme
            } else {
                Self::NotAUrl
            };
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        // The port, if there is one, and not the colons of an IPv6 address: those are inside brackets.
        let host = match authority.rsplit_once(':') {
            Some((host, port)) if !host.ends_with(':') && port.chars().all(char::is_numeric) => {
                host
            }
            _ => authority,
        }
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_lowercase();
        if host.is_empty() {
            return Self::NotAUrl;
        }
        if is_private(&host) {
            Self::Fine
        } else {
            Self::ClearOverTheInternet
        }
    }
}

/// Whether a host cannot be reached from outside this machine or this network.
fn is_private(host: &str) -> bool {
    if host == "localhost"
        || host == "::1"
        || host.ends_with(".local")
        || host.ends_with(".localhost")
    {
        return true;
    }
    let mut octets = host.split('.');
    let first: Option<u8> = octets.next().and_then(|part| part.parse().ok());
    let second: Option<u8> = octets.next().and_then(|part| part.parse().ok());
    // Four parts, all numbers, or it is a name and not an address.
    let numeric = octets.clone().count() == 2 && octets.all(|part| part.parse::<u8>().is_ok());
    match (first, second, numeric) {
        (Some(127), _, true) => true,
        (Some(10), _, true) => true,
        (Some(192), Some(168), true) => true,
        (Some(172), Some(second), true) => (16..=31).contains(&second),
        _ => false,
    }
}

/// Reads the configuration, filling in the defaults for anything never written.
pub(crate) fn read(connection: &Connection) -> Result<Ask> {
    let mut configuration = Ask::fresh();
    let get = |key: &str| -> Result<Option<String>> {
        Ok(connection
            .query_row(
                "SELECT value FROM ask WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()?)
    };
    if let Some(value) = get("enabled")? {
        configuration.enabled = value == "1";
    }
    if let Some(value) = get("kind")?
        && let Some(kind) = Kind::parse(&value)
    {
        configuration.kind = kind;
    }
    configuration.endpoint = get("endpoint")?.filter(|value| !value.is_empty());
    configuration.model = get("model")?.filter(|value| !value.is_empty());
    Ok(configuration)
}

/// Writes it.
pub(crate) fn write(connection: &Connection, configuration: &Ask) -> Result<()> {
    let mut put = connection.prepare("INSERT OR REPLACE INTO ask (key, value) VALUES (?1, ?2)")?;
    put.execute(params![
        "enabled",
        if configuration.enabled { "1" } else { "0" }
    ])?;
    put.execute(params!["kind", configuration.kind.as_str()])?;
    put.execute(params![
        "endpoint",
        configuration.endpoint.clone().unwrap_or_default()
    ])?;
    put.execute(params![
        "model",
        configuration.model.clone().unwrap_or_default()
    ])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The carve-out this whole module exists for: there is no model, so nothing is configured and nothing
    /// is guessed at.
    #[test]
    fn nothing_is_configured_until_somebody_configures_it() {
        let ask = Ask::fresh();
        assert!(!ask.enabled);
        assert_eq!(ask.endpoint, None);
        assert_eq!(ask.model, None);
        assert!(!ask.ready(true));
        assert!(
            ask.why_not(true, Language::English)
                .is_some_and(|why| why.contains("no model"))
        );
    }

    /// A provider that needs a key and has none is not ready, and says which of the two it is missing.
    #[test]
    fn a_hosted_provider_without_a_key_is_not_ready() {
        let ask = Ask {
            enabled: true,
            kind: Kind::Anthropic,
            endpoint: Some("https://api.anthropic.com/v1/messages".to_owned()),
            model: Some("claude-sonnet-5".to_owned()),
        };
        assert!(!ask.ready(false));
        assert!(
            ask.why_not(false, Language::English)
                .is_some_and(|why| why.contains("key"))
        );
        assert!(ask.ready(true));
        assert_eq!(ask.why_not(true, Language::English), None);
    }

    /// A local server needs no key, because nothing leaves.
    #[test]
    fn a_local_server_needs_no_key() {
        let ask = Ask {
            enabled: true,
            kind: Kind::Local,
            endpoint: Some(LOCAL_ENDPOINT.to_owned()),
            model: Some("llama3.2".to_owned()),
        };
        assert!(ask.ready(false));
        assert!(!ask.kind.sends_off_the_machine());
    }

    /// A model name is never guessed. Every provider has to be told which one, because the wrong guess is a
    /// 404 that reads like a broken feature.
    #[test]
    fn a_model_name_is_never_assumed() {
        let ask = Ask {
            enabled: true,
            kind: Kind::Local,
            endpoint: Some(LOCAL_ENDPOINT.to_owned()),
            model: None,
        };
        assert!(!ask.ready(true));
        assert!(
            ask.why_not(true, Language::English)
                .is_some_and(|why| why.contains("model"))
        );
    }

    /// A key and a question about this machine's traffic must not cross the network in the clear.
    #[test]
    fn plain_http_is_allowed_only_where_there_is_no_network_to_listen_on() {
        for private in [
            "http://127.0.0.1:11434/v1/chat/completions",
            "http://localhost:8080/v1/chat/completions",
            "http://10.1.2.3:11434/v1",
            "http://192.168.1.9:11434/v1",
            "http://172.16.0.4:11434/v1",
            "http://172.31.255.255:11434/v1",
            "http://workstation.local:11434/v1",
        ] {
            assert_eq!(Safety::of(private, Kind::Local), Safety::Fine, "{private}");
        }
        for public in [
            "http://api.openai.com/v1/chat/completions",
            "http://8.8.8.8/v1",
            "http://172.32.0.1/v1",
            "http://172.15.0.1/v1",
        ] {
            assert_eq!(
                Safety::of(public, Kind::Compatible),
                Safety::ClearOverTheInternet,
                "{public}"
            );
        }
        assert_eq!(
            Safety::of(
                "https://api.openai.com/v1/chat/completions",
                Kind::Compatible
            ),
            Safety::Fine
        );
        assert_eq!(
            Safety::of("ws://localhost/v1", Kind::Local),
            Safety::WrongScheme
        );
        assert_eq!(Safety::of("127.0.0.1:11434", Kind::Local), Safety::NotAUrl);
    }

    /// An endpoint that cannot be sent to stops the feature rather than being tried and failing.
    #[test]
    fn an_unsafe_endpoint_is_not_ready_and_says_why() {
        let ask = Ask {
            enabled: true,
            kind: Kind::Compatible,
            endpoint: Some("http://somebody.example/v1/chat/completions".to_owned()),
            model: Some("a-model".to_owned()),
        };
        assert!(!ask.ready(true));
        assert!(
            ask.why_not(true, Language::English)
                .is_some_and(|why| why.contains("in the clear"))
        );
    }

    /// The disclosure says what leaves and what does not, and says it differently for the case where
    /// nothing leaves.
    #[test]
    fn the_disclosure_distinguishes_the_case_where_nothing_leaves() {
        let local = Ask {
            enabled: true,
            kind: Kind::Local,
            endpoint: Some(LOCAL_ENDPOINT.to_owned()),
            model: Some("llama3.2".to_owned()),
        };
        let said = local.disclose(Language::English).join(" ");
        assert!(said.contains("Nothing crosses the internet"));
        assert!(said.contains("never a request target") || said.contains("Never a row"));

        let hosted = Ask {
            kind: Kind::Anthropic,
            endpoint: Some("https://api.anthropic.com/v1/messages".to_owned()),
            ..local
        };
        let said = hosted.disclose(Language::English).join(" ");
        assert!(said.contains("will be sent to https://api.anthropic.com/v1/messages"));
        // And that Flowlight records its own connection to the provider, which is the thing it would be
        // easiest to leave out.
        assert!(said.contains("attributed to flowlightd"));
    }

    #[test]
    fn a_kind_reads_back_from_what_it_is_written_as() {
        for kind in EVERY_KIND {
            assert_eq!(Kind::parse(kind.as_str()), Some(*kind));
        }
        assert_eq!(Kind::parse("  ANTHROPIC "), Some(Kind::Anthropic));
        assert_eq!(Kind::parse("ollama"), None);
    }
}
