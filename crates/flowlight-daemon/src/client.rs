//! Asking the running daemon something, from a command that is not it.
//!
//! One JSON object per line over the same Unix socket the window uses. It exists because `launch` runs as a
//! person rather than as root: it cannot open the database, so everything it needs to know it has to ask for.
//!
//! Deliberately tiny. There is one request and one reply per connection, and the alternative — sharing the
//! window's client — would mean the daemon depending on the interface, which is the wrong way round.

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;

/// As much of the interception view as anything outside the daemon reads.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct InterceptReply {
    /// Whether anything is being terminated.
    #[serde(default)]
    pub running: bool,
    /// The agents in scope.
    #[serde(default)]
    pub agents: Vec<String>,
    /// Where the bundle is.
    #[serde(default)]
    pub bundle: Option<String>,
}

/// What the daemon answers with: one or the other, never both.
#[derive(Deserialize)]
struct Reply<T> {
    ok: Option<T>,
    error: Option<String>,
}

/// Asks one question and reads one answer.
pub fn ask<T: serde::de::DeserializeOwned>(socket: &Path, request: &str) -> Result<T> {
    let mut stream = UnixStream::connect(socket).with_context(|| {
        format!(
            "connecting to {}. A daemon has to be running, and this has to be the person who started it — \
             the socket has an owner and the kernel checks it.",
            socket.display()
        )
    })?;
    stream
        .write_all(format!("{request}\n").as_bytes())
        .context("asking the daemon")?;
    let mut line = String::new();
    BufReader::new(&stream)
        .read_line(&mut line)
        .context("reading the daemon's answer")?;
    let reply: Reply<T> = serde_json::from_str(&line)
        .with_context(|| format!("reading `{}` as an answer", line.trim()))?;
    match (reply.ok, reply.error) {
        (Some(answer), _) => Ok(answer),
        (None, Some(why)) => bail!("{why}"),
        (None, None) => bail!("the daemon answered with neither an answer nor a reason"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_socket_says_what_it_needs() {
        let failed = ask::<bool>(
            Path::new("/nonexistent/flowlight.sock"),
            r#"{"op":"hello"}"#,
        );
        let said = format!("{:#}", failed.unwrap_err());
        assert!(said.contains("has to be running"), "{said}");
    }

    /// An answer and a reason are the two shapes, and a reason has to come back as an error rather than as a
    /// default value: a `mark` that failed and read as `false` would start an agent nothing was governing.
    #[test]
    fn a_reason_is_an_error_and_not_a_default() {
        let reply: Reply<bool> = serde_json::from_str(r#"{"error":"no such process"}"#).unwrap();
        assert!(reply.ok.is_none());
        assert_eq!(reply.error.as_deref(), Some("no such process"));

        let reply: Reply<bool> = serde_json::from_str(r#"{"ok":true}"#).unwrap();
        assert_eq!(reply.ok, Some(true));
        assert!(reply.error.is_none());
    }

    #[test]
    fn an_interception_reply_reads_what_launching_needs_and_ignores_the_rest() {
        let view: InterceptReply = serde_json::from_str(
            r#"{"enabled":true,"running":true,"port":7891,"agents":["claude"],"never":[],
                "disclosure":["something"],"bundle":"/share/ca-bundle.pem"}"#,
        )
        .unwrap();
        assert!(view.running);
        assert_eq!(view.agents, vec!["claude".to_owned()]);
        assert_eq!(view.bundle.as_deref(), Some("/share/ca-bundle.pem"));
    }
}
