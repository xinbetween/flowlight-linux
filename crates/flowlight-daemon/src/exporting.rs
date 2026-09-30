//! Sending what was seen somewhere else.
//!
//! [`flowlight_store::Export`] decides whether anything may leave and what it may say. This does the leaving:
//! it reads the records that have not been sent, renders only the fields somebody agreed to, delivers them to
//! a file or an OTLP collector, and moves a high-water mark afterwards.
//!
//! # Why the mark moves afterwards
//!
//! Because a batch that failed has not been sent. Marking first and delivering second loses records on every
//! network hiccup, silently, in exactly the situation somebody set up export to survive.
//!
//! # Why the mark is an identifier and not a time
//!
//! Two records can share a second. A watermark on time either sends one of them twice or neither, and which
//! one it is depends on the order rows come back in.
//!
//! # Why rendering is not serde
//!
//! [`flowlight_store::RequestRow`] has fields that must not travel unless they were named. A `#[derive]`
//! writes down everything a struct has, and the only way to make that safe is to remember, at every future
//! change to that struct, that adding a field to it silently adds a field to somebody's collector. Building
//! the object one agreed field at a time cannot make that mistake: a field nobody named is not in the loop.

use anyhow::{Context, Result};
use flowlight_store::export::{Field, Transport};
use flowlight_store::{Export, RequestRow, Store};
use serde_json::{Map, Value, json};
use std::io::Write;

/// How many records go in one batch.
///
/// Small enough that a collector refusing one batch loses one retry's worth of progress, and large enough
/// that a backlog drains in passes rather than in days.
const BATCH: usize = 256;

/// How long to wait for a collector before giving up on a batch.
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);

/// What one pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// How many records were delivered.
    pub sent: usize,
    /// What went wrong, if anything did.
    pub failure: Option<String>,
    /// Whether there is more waiting, so the next pass should not wait for the timer.
    pub more: bool,
}

impl Report {
    /// Whether anything happened worth a line.
    pub fn is_quiet(&self) -> bool {
        self.sent == 0 && self.failure.is_none()
    }
}

/// Sends one batch, if anything may be sent and anything is waiting.
///
/// Returns nothing at all when export is off or unconsented — that is the ordinary state, and a daemon that
/// complained about it every few seconds would be training its reader to ignore the log.
pub fn pass(store: &mut Store) -> Option<Report> {
    let export = match store.export() {
        Ok(export) => export,
        Err(err) => {
            return Some(Report {
                failure: Some(format!("could not read the export configuration: {err:#}")),
                ..Report::default()
            });
        }
    };
    if !export.may_send() {
        return None;
    }
    let waiting = match store.requests_after(export.sent_through, BATCH) {
        Ok(waiting) => waiting,
        Err(err) => {
            return Some(Report {
                failure: Some(format!("could not read what has not been sent: {err:#}")),
                ..Report::default()
            });
        }
    };
    if waiting.is_empty() {
        return None;
    }

    let mark = waiting.last().map(|(id, _)| *id)?;
    let rows: Vec<&RequestRow> = waiting.iter().map(|(_, row)| row).collect();
    if let Err(err) = deliver(&export, &rows) {
        return Some(Report {
            failure: Some(format!("{err:#}")),
            ..Report::default()
        });
    }

    // Only now. Before delivery, this loses a batch on every hiccup.
    let mut moved = export;
    moved.sent_through = mark;
    if let Err(err) = store.set_export(&moved) {
        // The records went out and the mark did not move, so the next pass sends them again. Said out loud,
        // because a duplicate at the far end is a thing somebody has to know to explain.
        return Some(Report {
            sent: rows.len(),
            failure: Some(format!(
                "delivered, but could not record how far: {err:#}. The next batch will repeat these \
                 records."
            )),
            more: false,
        });
    }
    Some(Report {
        sent: rows.len(),
        failure: None,
        more: rows.len() == BATCH,
    })
}

/// Hands a batch to whatever the destination is.
fn deliver(export: &Export, rows: &[&RequestRow]) -> Result<()> {
    let destination = export
        .destination
        .as_deref()
        .context("no destination, which may_send() should already have refused")?;
    match export.transport() {
        Some(Transport::File) => to_file(destination, export, rows),
        Some(Transport::Otlp) => to_collector(destination, export, rows),
        None => anyhow::bail!("{destination} is neither an absolute path nor an http(s) URL"),
    }
}

/// Appends one JSON object per line. Nothing crosses the network.
fn to_file(path: &str, export: &Export, rows: &[&RequestRow]) -> Result<()> {
    let mut text = String::new();
    for row in rows {
        let object = render(row, export);
        text.push_str(&serde_json::to_string(&object)?);
        text.push('\n');
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {path} to append to it"))?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("writing to {path}"))?;
    Ok(())
}

/// Posts one OTLP/HTTP logs payload, as JSON.
///
/// JSON rather than protobuf because the wire format is a detail and a protobuf dependency is not: every
/// collector that speaks OTLP/HTTP accepts `application/json` at the same endpoint.
fn to_collector(url: &str, export: &Export, rows: &[&RequestRow]) -> Result<()> {
    let body = serde_json::to_string(&otlp(export, rows))?;
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(PATIENCE))
        .build()
        .new_agent();
    let mut request = agent.post(url).header("content-type", "application/json");
    for (name, value) in &export.headers {
        request = request.header(name, value);
    }
    let response = request
        .send(&body)
        .with_context(|| format!("posting {} record(s) to {url}", rows.len()))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        anyhow::bail!("{url} answered {status}");
    }
    Ok(())
}

/// The OTLP logs envelope.
fn otlp(export: &Export, rows: &[&RequestRow]) -> Value {
    let records: Vec<Value> = rows
        .iter()
        .map(|row| {
            let attributes: Vec<Value> = render(row, export)
                .into_iter()
                .map(|(key, value)| json!({ "key": key, "value": otlp_value(&value) }))
                .collect();
            json!({
                // Seconds are what was recorded; the extra nine digits are the format's, not a precision
                // claim.
                "timeUnixNano": (row.at.max(0) as u64 * 1_000_000_000).to_string(),
                "severityNumber": 9,
                "severityText": "INFO",
                "body": { "stringValue": summary(row, export) },
                "attributes": attributes,
            })
        })
        .collect();
    json!({
        "resourceLogs": [{
            "resource": { "attributes": [
                { "key": "service.name", "value": { "stringValue": "flowlight" } },
            ]},
            "scopeLogs": [{
                "scope": { "name": "flowlight", "version": env!("CARGO_PKG_VERSION") },
                "logRecords": records,
            }],
        }],
    })
}

/// An OTLP `AnyValue`.
fn otlp_value(value: &Value) -> Value {
    match value {
        Value::Number(number) if number.is_i64() => {
            json!({ "intValue": number.as_i64().unwrap_or_default().to_string() })
        }
        Value::Bool(flag) => json!({ "boolValue": flag }),
        other => json!({ "stringValue": other.as_str().unwrap_or_default() }),
    }
}

/// One line of body text, built only from fields that were agreed to.
fn summary(row: &RequestRow, export: &Export) -> String {
    let mut words = Vec::new();
    if export.fields.contains(&Field::Method) {
        words.extend(row.method.clone());
    }
    if export.fields.contains(&Field::Host) {
        words.extend(row.host.clone());
    }
    if export.fields.contains(&Field::Target) {
        words.extend(row.target.clone());
    }
    if words.is_empty() {
        // Not the process name, and not the host: neither may have been agreed to.
        return "a request".to_owned();
    }
    words.join(" ")
}

/// Builds the object for one record, one agreed field at a time.
///
/// Every arm names a field explicitly. Adding a field to [`RequestRow`] adds nothing here, which is the whole
/// point: a new column cannot leak by being new.
fn render(row: &RequestRow, export: &Export) -> Map<String, Value> {
    let mut object = Map::new();
    for field in &export.fields {
        let value = match field {
            Field::At => json!(row.at),
            Field::Process => json!(row.process),
            Field::Confidence => json!(row.confidence),
            Field::Pid => json!(row.pid),
            Field::Agent => match &row.agent {
                Some(agent) => json!(agent),
                None => continue,
            },
            Field::Direction => json!(row.direction),
            Field::Host => match &row.host {
                Some(host) => json!(host),
                None => continue,
            },
            Field::Method => match &row.method {
                Some(method) => json!(method),
                None => continue,
            },
            Field::Target => match &row.target {
                Some(target) => json!(target),
                None => continue,
            },
            Field::Status => match row.status {
                Some(status) => json!(status),
                None => continue,
            },
            Field::Bytes => json!(row.bytes),
            Field::Protocol => match &row.protocol {
                Some(protocol) => json!(protocol),
                None => continue,
            },
            Field::RpcMethod => match &row.rpc_method {
                Some(method) => json!(method),
                None => continue,
            },
            Field::RpcTool => match &row.rpc_tool {
                Some(tool) => json!(tool),
                None => continue,
            },
        };
        object.insert(field.as_str().to_owned(), value);
    }
    object
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowlight_store::export::DEFAULT_FIELDS;
    use std::path::{Path, PathBuf};

    /// A directory of its own for one test, removed afterwards.
    ///
    /// Hand-written rather than a dependency: this is four lines of what `tempfile` does, and a crate in the
    /// tree is a crate in the audit.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("flowlight-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        /// A path inside it, as the string a destination is.
        fn file(&self, name: &str) -> String {
            self.0.join(name).to_string_lossy().into_owned()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn row() -> RequestRow {
        RequestRow {
            at: 1_700_000_000,
            process: "node".to_owned(),
            confidence: "certain".to_owned(),
            pid: 4321,
            agent: Some("claude".to_owned()),
            direction: "out".to_owned(),
            protocol: Some("http/2".to_owned()),
            method: Some("POST".to_owned()),
            target: Some("/v1/messages".to_owned()),
            host: Some("api.anthropic.com".to_owned()),
            status: Some(200),
            bytes: 1024,
            truncated: false,
            unreadable: None,
            rpc_method: Some("tools/call".to_owned()),
            rpc_tool: Some("read_file".to_owned()),
        }
    }

    fn configured(destination: &str) -> Export {
        let mut export = Export::fresh();
        export.enabled = true;
        export.destination = Some(destination.to_owned());
        export.consented = Some(export.fingerprint());
        export
    }

    /// A field nobody named is not in the object. This is the property the whole module exists for.
    #[test]
    fn only_the_agreed_fields_are_rendered() {
        let export = configured("/tmp/x.jsonl");
        let object = render(&row(), &export);
        for field in DEFAULT_FIELDS {
            assert!(
                object.contains_key(field.as_str()),
                "{} was agreed to and is missing",
                field.as_str()
            );
        }
        for absent in ["target", "rpc_tool", "pid", "confidence", "protocol"] {
            assert!(!object.contains_key(absent), "{absent} was not agreed to");
        }
    }

    /// The failure a `#[derive]` would make: a field added to the row later travels without being named.
    #[test]
    fn a_field_travels_only_because_it_was_named() {
        let mut export = configured("/tmp/x.jsonl");
        assert!(!render(&row(), &export).contains_key("target"));
        export.fields.insert(Field::Target);
        assert_eq!(
            render(&row(), &export)
                .get("target")
                .and_then(Value::as_str),
            Some("/v1/messages")
        );
    }

    /// An absent value is an absent key, not a null. A collector's schema should not acquire a column of
    /// nulls because some requests have no response yet.
    #[test]
    fn nothing_is_written_down_as_nothing() {
        let export = configured("/tmp/x.jsonl");
        let mut row = row();
        row.status = None;
        row.host = None;
        let object = render(&row, &export);
        assert!(!object.contains_key("status"));
        assert!(!object.contains_key("host"));
        assert!(object.contains_key("process"));
    }

    #[test]
    fn a_file_destination_gets_one_json_object_per_line() {
        let directory = Scratch::new("lines");
        let name = directory.file("out.jsonl");
        let path = std::path::PathBuf::from(&name);
        let export = configured(&name);
        let first = row();
        let mut second = row();
        second.host = Some("github.com".to_owned());

        to_file(&name, &export, &[&first, &second]).unwrap();
        // Appended, not replaced: a restart must not truncate what was already delivered.
        to_file(&name, &export, &[&second]).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            let value: Value = serde_json::from_str(line).unwrap();
            assert!(value.get("at").is_some());
        }
        assert_eq!(
            serde_json::from_str::<Value>(lines[0])
                .unwrap()
                .get("host")
                .and_then(Value::as_str),
            Some("api.anthropic.com")
        );
    }

    /// The body is built from agreed fields too, or an unconsented target would travel inside a sentence.
    #[test]
    fn the_body_says_nothing_that_was_not_agreed_to() {
        let mut export = configured("https://collector.example/v1/logs");
        let body = summary(&row(), &export);
        assert_eq!(body, "POST api.anthropic.com");
        assert!(!body.contains("/v1/messages"));

        export.fields.remove(&Field::Method);
        export.fields.remove(&Field::Host);
        assert_eq!(summary(&row(), &export), "a request");
    }

    #[test]
    fn the_otlp_envelope_carries_the_records_as_attributes() {
        let export = configured("https://collector.example/v1/logs");
        let envelope = otlp(&export, &[&row()]);
        let records = envelope
            .pointer("/resourceLogs/0/scopeLogs/0/logRecords")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].pointer("/timeUnixNano").and_then(Value::as_str),
            Some("1700000000000000000")
        );
        let attributes = records[0]
            .pointer("/attributes")
            .and_then(Value::as_array)
            .unwrap();
        let keys: Vec<&str> = attributes
            .iter()
            .filter_map(|attribute| attribute.get("key").and_then(Value::as_str))
            .collect();
        assert!(keys.contains(&"host"));
        assert!(!keys.contains(&"target"));
        // Integers are OTLP integers, as strings, which is what the format says.
        let bytes = attributes
            .iter()
            .find(|attribute| attribute.get("key").and_then(Value::as_str) == Some("bytes"))
            .unwrap();
        assert_eq!(
            bytes.pointer("/value/intValue").and_then(Value::as_str),
            Some("1024")
        );
    }

    #[test]
    fn nothing_is_sent_when_nobody_agreed() {
        let mut store = Store::in_memory().unwrap();
        store.record_request(row()).unwrap();
        store.flush().unwrap();
        let directory = Scratch::new("unconsented");
        let name = directory.file("out.jsonl");
        let path = std::path::PathBuf::from(&name);

        let mut export = Export::fresh();
        export.enabled = true;
        export.destination = Some(name.clone());
        // No consent.
        store.set_export(&export).unwrap();
        assert_eq!(pass(&mut store), None);
        assert!(!path.exists());

        export.consented = Some(export.fingerprint());
        store.set_export(&export).unwrap();
        let report = pass(&mut store).unwrap();
        assert_eq!(report.sent, 1);
        assert_eq!(report.failure, None);
        assert!(path.exists());
    }

    /// The mark moves, so a second pass with nothing new sends nothing.
    #[test]
    fn a_record_is_sent_once() {
        let mut store = Store::in_memory().unwrap();
        store.record_request(row()).unwrap();
        let directory = Scratch::new("once");
        let name = directory.file("out.jsonl");
        store.set_export(&configured(&name)).unwrap();

        assert_eq!(pass(&mut store).unwrap().sent, 1);
        assert_eq!(pass(&mut store), None);
        assert!(store.export().unwrap().sent_through > 0);

        store.record_request(row()).unwrap();
        assert_eq!(pass(&mut store).unwrap().sent, 1);
        assert_eq!(std::fs::read_to_string(&name).unwrap().lines().count(), 2);
    }

    /// A batch that could not be delivered has not been sent, so the mark must not have moved.
    #[test]
    fn a_failed_batch_is_not_marked_as_sent() {
        let mut store = Store::in_memory().unwrap();
        store.record_request(row()).unwrap();
        let directory = Scratch::new("unsent");
        // A directory, not a file: opening it to append fails.
        let name = directory.path().to_string_lossy().into_owned();
        store.set_export(&configured(&name)).unwrap();

        let report = pass(&mut store).unwrap();
        assert_eq!(report.sent, 0);
        assert!(report.failure.is_some());
        assert_eq!(store.export().unwrap().sent_through, 0);
    }
}
