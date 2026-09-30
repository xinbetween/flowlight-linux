//! Sending what was seen somewhere else, and what somebody agreed to when they said yes.
//!
//! Export is the one feature here that takes data off the machine. Everything else is a local answer to a
//! local question; this is a decision to hand every request an agent made to somewhere else, and it should
//! be as hard to do by accident as that deserves.
//!
//! # Consent is bound to the disclosure, not to the act
//!
//! The obvious design is a switch: turn export on, and it exports. The failure that design invites is
//! somebody agreeing to send four fields to their own collector, and then — three weeks and one
//! configuration change later — sending eleven fields to somebody else's, still under the original yes.
//!
//! So a [`Fingerprint`] is taken over exactly what was disclosed: the destination, the transport, the
//! fields, and the *names* of the headers. Consent records that fingerprint. Change any of it and the
//! fingerprint changes, the recorded consent no longer matches, and **nothing is sent until somebody agrees
//! to the new sentence**. This is the shape the macOS build arrived at in its 0.9.5, and it is worth copying
//! exactly rather than approximately.
//!
//! Header *values* are deliberately not in the fingerprint and never in the disclosure. A token is a secret,
//! not a description of where data goes, and rotating one is not a change anybody should have to re-consent
//! to.
//!
//! # What does not travel by default
//!
//! Paths, tool names, and process identifiers. Each of them says something about the *work* rather than the
//! shape of it, and each is available by asking for it explicitly. The default set is the one that answers
//! "which agent talked to what, how often, and did it succeed".

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension as _, params};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// One thing that can travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    /// When it happened.
    At,
    /// What the process is called.
    Process,
    /// Where that name came from.
    Confidence,
    /// The process identifier.
    Pid,
    /// The agent that caused it.
    Agent,
    /// Out or in.
    Direction,
    /// The host.
    Host,
    /// The request method.
    Method,
    /// The request target, credentials already removed.
    Target,
    /// The response status.
    Status,
    /// How many bytes.
    Bytes,
    /// Whether the connection was HTTP/2.
    Protocol,
    /// The JSON-RPC method, for MCP.
    RpcMethod,
    /// The tool, for an MCP call.
    RpcTool,
}

/// Every field, in the order a disclosure names them.
pub const EVERY_FIELD: &[Field] = &[
    Field::At,
    Field::Process,
    Field::Confidence,
    Field::Pid,
    Field::Agent,
    Field::Direction,
    Field::Host,
    Field::Method,
    Field::Target,
    Field::Status,
    Field::Bytes,
    Field::Protocol,
    Field::RpcMethod,
    Field::RpcTool,
];

/// The fields that travel unless somebody asks for more.
///
/// The set that answers "which agent talked to what, how often, and did it succeed". Not paths, not tool
/// names, not process identifiers: each of those says something about the work rather than the shape of it.
pub const DEFAULT_FIELDS: &[Field] = &[
    Field::At,
    Field::Process,
    Field::Agent,
    Field::Direction,
    Field::Host,
    Field::Method,
    Field::Status,
    Field::Bytes,
];

impl Field {
    /// The name this is written down and disclosed under.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::At => "at",
            Self::Process => "process",
            Self::Confidence => "confidence",
            Self::Pid => "pid",
            Self::Agent => "agent",
            Self::Direction => "direction",
            Self::Host => "host",
            Self::Method => "method",
            Self::Target => "target",
            Self::Status => "status",
            Self::Bytes => "bytes",
            Self::Protocol => "protocol",
            Self::RpcMethod => "rpc_method",
            Self::RpcTool => "rpc_tool",
        }
    }

    /// How this reads in a sentence.
    fn described(self) -> &'static str {
        match self {
            Self::At => "when",
            Self::Process => "the process",
            Self::Confidence => "how the process was named",
            Self::Pid => "the process identifier",
            Self::Agent => "the agent",
            Self::Direction => "the direction",
            Self::Host => "the host",
            Self::Method => "the method",
            Self::Target => "the path",
            Self::Status => "the status",
            Self::Bytes => "the size",
            Self::Protocol => "the protocol",
            Self::RpcMethod => "the MCP method",
            Self::RpcTool => "the tool's name",
        }
    }

    /// Reads one back, or nothing if it is not one.
    pub fn parse(text: &str) -> Option<Self> {
        EVERY_FIELD
            .iter()
            .copied()
            .find(|field| field.as_str() == text)
    }
}

/// How a destination is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// A file on this machine, one JSON object per line. Nothing crosses the network.
    File,
    /// OTLP over HTTP, as JSON. Something does.
    Otlp,
}

impl Transport {
    /// The name this is disclosed under, which is part of what somebody agrees to.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Otlp => "otlp",
        }
    }

    /// What a destination says it is.
    ///
    /// A path is a file and a URL is a collector. Guessing wrong in the direction of the network would be
    /// the worse mistake, so anything that is not plainly a path is refused rather than assumed.
    pub fn of(destination: &str) -> Option<Self> {
        if destination.starts_with("http://") || destination.starts_with("https://") {
            Some(Self::Otlp)
        } else if destination.starts_with('/') {
            Some(Self::File)
        } else {
            None
        }
    }
}

/// A hash of everything that was disclosed.
///
/// Sixteen bytes of SHA-256, as hex. Not a secret and not a checksum of the data — a name for one exact
/// sentence, so that agreeing to that sentence can be told apart from agreeing to a different one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint(pub String);

/// Where what was seen is sent, and what somebody agreed to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Export {
    /// Whether export is wanted at all.
    pub enabled: bool,
    /// The destination: a URL for a collector, or an absolute path for a file.
    pub destination: Option<String>,
    /// What travels.
    pub fields: BTreeSet<Field>,
    /// Headers sent with each batch. The names are disclosed; the values never are.
    pub headers: BTreeMap<String, String>,
    /// The fingerprint somebody agreed to, if anybody has.
    pub consented: Option<Fingerprint>,
    /// The identifier of the last record sent, so nothing is sent twice.
    pub sent_through: i64,
}

impl Export {
    /// An export nobody has configured, with the default fields already chosen.
    pub fn fresh() -> Self {
        Self {
            fields: DEFAULT_FIELDS.iter().copied().collect(),
            ..Self::default()
        }
    }

    /// How this destination is reached.
    pub fn transport(&self) -> Option<Transport> {
        self.destination.as_deref().and_then(Transport::of)
    }

    /// A hash of everything the disclosure says.
    ///
    /// The destination, the transport, the fields, and the *names* of the headers — each separated by a byte
    /// that cannot appear in any of them, so that two different configurations cannot hash the same by
    /// running into one another.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut hasher = Sha256::new();
        hasher.update(self.destination.as_deref().unwrap_or("").as_bytes());
        hasher.update([0]);
        hasher.update(
            self.transport()
                .map_or("none", Transport::as_str)
                .as_bytes(),
        );
        hasher.update([0]);
        for field in &self.fields {
            hasher.update(field.as_str().as_bytes());
            hasher.update([0x1f]);
        }
        hasher.update([0]);
        // Names, never values. A token is a secret, not a description of where data goes, and rotating one
        // is not a change anybody should have to agree to again.
        for name in self.headers.keys() {
            hasher.update(name.to_ascii_lowercase().as_bytes());
            hasher.update([0x1f]);
        }
        Fingerprint(
            hasher
                .finalize()
                .iter()
                .take(16)
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        )
    }

    /// Whether anything may be sent right now.
    ///
    /// Four things have to be true, and the fourth is the one that matters: the consent on record has to be
    /// for the configuration in force, not for some earlier one.
    pub fn may_send(&self) -> bool {
        self.enabled
            && self.destination.is_some()
            && self.transport().is_some()
            && self.consented.as_ref() == Some(&self.fingerprint())
    }

    /// Why nothing is being sent, when nothing is.
    pub fn why_not(&self) -> Option<String> {
        if self.may_send() {
            return None;
        }
        Some(if !self.enabled {
            "Export is off.".to_owned()
        } else if self.destination.is_none() {
            "No destination has been set, so there is nowhere to send anything.".to_owned()
        } else if self.transport().is_none() {
            "The destination is neither an http:// or https:// collector nor an absolute file path, so it \
             is not clear what sending to it would mean."
                .to_owned()
        } else if self.consented.is_none() {
            "Nobody has agreed to this yet. Nothing is sent until somebody does.".to_owned()
        } else {
            "What is being sent, or where, has changed since somebody agreed to it. Nothing is sent until \
             somebody agrees to what it is now."
                .to_owned()
        })
    }

    /// What somebody is being asked to agree to, in sentences.
    ///
    /// Every sentence is a complete one and says a thing that is true. The list of what does *not* travel is
    /// there on purpose: a disclosure that only says what it takes invites the reader to assume the rest.
    pub fn disclose(&self) -> Vec<String> {
        let mut said = Vec::new();
        let Some(destination) = self.destination.as_deref() else {
            said.push("No destination has been set, so nothing can be sent anywhere.".to_owned());
            return said;
        };

        said.push(match self.transport() {
            Some(Transport::Otlp) => format!(
                "Every request Flowlight reads will be sent over the network to {destination}, as OTLP."
            ),
            Some(Transport::File) => format!(
                "Every request Flowlight reads will be written to {destination}, one line each. Nothing \
                 crosses the network."
            ),
            None => format!(
                "{destination} is neither a collector nor an absolute file path, so nothing can be sent to \
                 it."
            ),
        });

        let travelling: Vec<&str> = EVERY_FIELD
            .iter()
            .filter(|field| self.fields.contains(field))
            .map(|field| field.described())
            .collect();
        said.push(if travelling.is_empty() {
            "No fields travel, which means each record would say nothing at all.".to_owned()
        } else {
            format!(
                "{} {} travel: {}.",
                count(travelling.len()),
                if travelling.len() == 1 {
                    "field"
                } else {
                    "fields"
                },
                travelling.join(", ")
            )
        });

        let withheld: Vec<&str> = EVERY_FIELD
            .iter()
            .filter(|field| !self.fields.contains(field))
            .map(|field| field.described())
            .collect();
        if !withheld.is_empty() {
            said.push(format!("These do not: {}.", withheld.join(", ")));
        }

        if !self.headers.is_empty() {
            let names: Vec<&str> = self.headers.keys().map(String::as_str).collect();
            said.push(format!(
                "{} {} sent with each batch: {}. The values are not shown here and are not part of what \
                 you are agreeing to.",
                count(names.len()),
                if names.len() == 1 {
                    "header is"
                } else {
                    "headers are"
                },
                names.join(", ")
            ));
        }

        said.push(
            "This agreement is bound to exactly that. Changing the destination, the fields or the headers \
             stops the export until somebody agrees again."
                .to_owned(),
        );
        said
    }
}

/// A small number, in words, because a sentence that starts with a digit reads like a log line.
fn count(many: usize) -> &'static str {
    match many {
        0 => "No",
        1 => "One",
        2 => "Two",
        3 => "Three",
        4 => "Four",
        5 => "Five",
        6 => "Six",
        7 => "Seven",
        8 => "Eight",
        9 => "Nine",
        10 => "Ten",
        11 => "Eleven",
        12 => "Twelve",
        13 => "Thirteen",
        14 => "Fourteen",
        _ => "Several",
    }
}

/// Reads the export configuration, filling in the defaults for anything never written.
pub(crate) fn read(connection: &Connection) -> Result<Export> {
    let mut export = Export::fresh();
    let get = |key: &str| -> Result<Option<String>> {
        Ok(connection
            .query_row(
                "SELECT value FROM export WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()?)
    };
    if let Some(value) = get("enabled")? {
        export.enabled = value == "true";
    }
    export.destination = get("destination")?.filter(|value| !value.is_empty());
    if let Some(value) = get("fields")? {
        export.fields = value.split(',').filter_map(Field::parse).collect();
    }
    if let Some(value) = get("headers")? {
        export.headers = value
            .lines()
            .filter_map(|line| line.split_once('\t'))
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect();
    }
    export.consented = get("consented")?
        .filter(|value| !value.is_empty())
        .map(Fingerprint);
    if let Some(value) = get("sent_through")?.and_then(|v| v.parse().ok()) {
        export.sent_through = value;
    }
    Ok(export)
}

/// Writes the export configuration, every field of it.
pub(crate) fn write(connection: &Connection, export: &Export) -> Result<()> {
    let fields = export
        .fields
        .iter()
        .map(|field| field.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let headers = export
        .headers
        .iter()
        .map(|(name, value)| format!("{name}\t{value}"))
        .collect::<Vec<_>>()
        .join("\n");
    for (key, value) in [
        ("enabled", export.enabled.to_string()),
        (
            "destination",
            export.destination.clone().unwrap_or_default(),
        ),
        ("fields", fields),
        ("headers", headers),
        (
            "consented",
            export
                .consented
                .as_ref()
                .map(|print| print.0.clone())
                .unwrap_or_default(),
        ),
        ("sent_through", export.sent_through.to_string()),
    ] {
        connection.execute(
            "INSERT INTO export(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured() -> Export {
        Export {
            enabled: true,
            destination: Some("https://otel.example.com/v1/logs".to_owned()),
            ..Export::fresh()
        }
    }

    /// Nothing leaves until somebody has agreed to the sentence describing what leaves.
    #[test]
    fn nothing_is_sent_without_consent() {
        let export = configured();
        assert!(!export.may_send());
        assert!(
            export
                .why_not()
                .is_some_and(|why| why.contains("Nobody has agreed"))
        );
    }

    #[test]
    fn consent_to_what_is_configured_is_consent() {
        let mut export = configured();
        export.consented = Some(export.fingerprint());
        assert!(export.may_send());
        assert_eq!(export.why_not(), None);
    }

    /// The failure the whole design exists to prevent: somebody agrees to four fields going to their own
    /// collector, and three weeks later eleven fields go to somebody else's under the same yes.
    #[test]
    fn changing_where_it_goes_takes_the_consent_with_it() {
        let mut export = configured();
        export.consented = Some(export.fingerprint());
        assert!(export.may_send());

        export.destination = Some("https://somewhere.else/v1/logs".to_owned());
        assert!(!export.may_send());
        assert!(
            export
                .why_not()
                .is_some_and(|why| why.contains("has changed since somebody agreed"))
        );
    }

    #[test]
    fn adding_a_field_takes_the_consent_with_it() {
        let mut export = configured();
        export.consented = Some(export.fingerprint());
        export.fields.insert(Field::Target);
        assert!(!export.may_send());
    }

    #[test]
    fn removing_a_field_takes_the_consent_with_it() {
        let mut export = configured();
        export.consented = Some(export.fingerprint());
        export.fields.remove(&Field::Host);
        assert!(!export.may_send());
    }

    #[test]
    fn adding_a_header_takes_the_consent_with_it() {
        let mut export = configured();
        export.consented = Some(export.fingerprint());
        export
            .headers
            .insert("authorization".to_owned(), "Bearer x".to_owned());
        assert!(!export.may_send());
    }

    /// A token is a secret, not a description of where data goes. Rotating one is not a change anybody
    /// should have to agree to again.
    #[test]
    fn changing_a_header_value_does_not() {
        let mut export = configured();
        export
            .headers
            .insert("authorization".to_owned(), "Bearer old".to_owned());
        export.consented = Some(export.fingerprint());
        assert!(export.may_send());

        export
            .headers
            .insert("authorization".to_owned(), "Bearer new".to_owned());
        assert!(
            export.may_send(),
            "rotating a token should not revoke consent"
        );
    }

    /// Two configurations that differ must not hash the same by running into one another.
    #[test]
    fn fields_that_run_together_are_still_different_configurations() {
        let mut one = configured();
        one.fields = [Field::At, Field::Process].into_iter().collect();
        let mut two = configured();
        two.fields = [Field::Agent].into_iter().collect();
        assert_ne!(one.fingerprint(), two.fingerprint());

        // And a destination that ends where a transport name begins.
        let mut three = configured();
        three.destination = Some("/tmp/aotlp".to_owned());
        let mut four = configured();
        four.destination = Some("/tmp/a".to_owned());
        assert_ne!(three.fingerprint(), four.fingerprint());
    }

    /// Guessing wrong in the direction of the network would be the worse mistake.
    #[test]
    fn a_destination_that_is_neither_one_thing_nor_the_other_is_refused() {
        assert_eq!(
            Transport::of("https://a.example/v1/logs"),
            Some(Transport::Otlp)
        );
        assert_eq!(
            Transport::of("/var/log/flowlight.jsonl"),
            Some(Transport::File)
        );
        for destination in ["a.example", "otel.example.com:4318", "~/log.jsonl", ""] {
            assert_eq!(Transport::of(destination), None, "{destination}");
        }

        let mut export = configured();
        export.destination = Some("otel.example.com".to_owned());
        export.consented = Some(export.fingerprint());
        assert!(!export.may_send());
        assert!(
            export
                .why_not()
                .is_some_and(|why| why.contains("not clear"))
        );
    }

    /// A disclosure that only says what it takes invites the reader to assume the rest.
    #[test]
    fn the_disclosure_says_what_does_not_travel_as_well() {
        let said = configured().disclose();
        let whole = said.join(" ");
        assert!(
            whole.contains("over the network to https://otel.example.com/v1/logs"),
            "{whole}"
        );
        assert!(whole.contains("Eight fields travel"), "{whole}");
        assert!(whole.contains("These do not:"), "{whole}");
        assert!(whole.contains("the path"), "{whole}");
        assert!(whole.contains("the tool's name"), "{whole}");
        assert!(whole.contains("bound to exactly that"), "{whole}");
        for sentence in &said {
            assert!(sentence.ends_with('.'), "not a sentence: {sentence}");
        }
    }

    /// A file destination has to say that nothing crosses the network, because that is the thing somebody
    /// would otherwise be agreeing to unnecessarily.
    #[test]
    fn a_file_destination_says_nothing_crosses_the_network() {
        let mut export = configured();
        export.destination = Some("/var/log/flowlight.jsonl".to_owned());
        let whole = export.disclose().join(" ");
        assert!(
            whole.contains("Nothing \ncrosses the network.")
                || whole.contains("Nothing crosses the network."),
            "{whole}"
        );
    }

    /// Header values are never in the disclosure, because a disclosure is read aloud and shown in
    /// screenshots.
    #[test]
    fn a_header_value_is_never_disclosed() {
        let mut export = configured();
        export
            .headers
            .insert("authorization".to_owned(), "Bearer hunter2".to_owned());
        let whole = export.disclose().join(" ");
        assert!(whole.contains("authorization"), "{whole}");
        assert!(!whole.contains("hunter2"), "{whole}");
        assert!(whole.contains("values are not shown here"), "{whole}");
    }

    #[test]
    fn an_export_with_no_destination_says_so_rather_than_describing_one() {
        let said = Export::fresh().disclose();
        assert_eq!(said.len(), 1);
        assert!(said[0].contains("No destination has been set"));
    }

    #[test]
    fn every_field_survives_being_written_down_and_read_back() {
        for field in EVERY_FIELD {
            assert_eq!(Field::parse(field.as_str()), Some(*field));
        }
        assert_eq!(Field::parse("something"), None);
    }
}
