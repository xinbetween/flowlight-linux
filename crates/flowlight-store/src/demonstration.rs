//! A database that looks like a working afternoon, so that a tool which watches a private machine can be
//! shown to somebody at all.
//!
//! Every screenshot of Flowlight is a screenshot of whoever took it: the hosts an agent reached, the
//! repositories it cloned, the paths it asked for. The honest way to publish one is to have something to
//! photograph that is not anybody's afternoon.
//!
//! # It is a separate database, and it says so
//!
//! Nothing here writes into a database that holds real traffic. A demonstration is written to a path somebody
//! names, the file must not already exist, and the database is marked — `meta demo = 1` — for as long as it
//! exists. Every command that reads a marked database says so before it says anything else, and the daemon
//! **refuses to watch into one**: mixing real traffic into a demonstration would leave two things that cannot
//! be told apart, and the one people would believe is the wrong one.
//!
//! That refusal is the whole design. The macOS build learnt it the hard way — a demonstration run there once
//! reached into the real app's state on the way out — and the lesson is that a demonstration mode must be
//! unable to touch the thing it is imitating, rather than careful not to.
//!
//! # Deterministic
//!
//! The same arguments produce the same database, from a small generator written here rather than a dependency.
//! A screenshot that has to be retaken should be retakeable, and a test that asserts what was generated should
//! be able to.

use crate::{ConnectionRow, RequestRow, Store};
use anyhow::{Result, bail};
use std::path::Path;

/// What a demonstration is made of, so that the numbers in it are not accidental.
struct Scene {
    /// The process that made the call.
    process: &'static str,
    /// What it works for, when it works for something.
    agent: Option<&'static str>,
    /// Where it went.
    host: &'static str,
    /// The address behind it, as the kernel would have recorded.
    address: &'static str,
    /// The method and the path.
    method: &'static str,
    /// The path.
    target: &'static str,
    /// What came back.
    status: u16,
    /// Roughly how big, before the generator varies it.
    bytes: u32,
    /// The JSON-RPC method, when this was said to an MCP server.
    rpc: Option<(&'static str, Option<&'static str>)>,
}

/// One afternoon, as a list. Read it top to bottom and it is a session: a model answering, a package
/// installed, a repository read, a tool called over MCP, and one thing that went somewhere nobody expected.
const SCENES: &[Scene] = &[
    Scene {
        process: "node",
        agent: Some("claude"),
        host: "api.anthropic.com",
        address: "160.79.104.10",
        method: "POST",
        target: "/v1/messages",
        status: 200,
        bytes: 24_100,
        rpc: None,
    },
    Scene {
        process: "node",
        agent: Some("claude"),
        host: "registry.npmjs.org",
        address: "104.16.24.35",
        method: "GET",
        target: "/@modelcontextprotocol%2fsdk",
        status: 200,
        bytes: 8_400,
        rpc: None,
    },
    Scene {
        process: "git",
        agent: Some("claude"),
        host: "github.com",
        address: "140.82.121.4",
        method: "POST",
        target: "/xinbetween/flowlight-linux.git/git-upload-pack",
        status: 200,
        bytes: 412_000,
        rpc: None,
    },
    Scene {
        process: "node",
        agent: Some("claude"),
        host: "mcp.internal.example",
        address: "10.0.4.19",
        method: "POST",
        target: "/rpc",
        status: 200,
        bytes: 1_900,
        rpc: Some(("tools/call", Some("read_file"))),
    },
    Scene {
        process: "node",
        agent: Some("claude"),
        host: "mcp.internal.example",
        address: "10.0.4.19",
        method: "POST",
        target: "/rpc",
        status: 200,
        bytes: 640,
        rpc: Some(("tools/list", None)),
    },
    Scene {
        process: "python3",
        agent: Some("codex"),
        host: "api.openai.com",
        address: "162.159.140.245",
        method: "POST",
        target: "/v1/responses",
        status: 200,
        bytes: 31_500,
        rpc: None,
    },
    Scene {
        process: "python3",
        agent: Some("codex"),
        host: "files.pythonhosted.org",
        address: "151.101.0.223",
        method: "GET",
        target: "/packages/httpx-0.27.0-py3-none-any.whl",
        status: 200,
        bytes: 126_000,
        rpc: None,
    },
    Scene {
        process: "curl",
        agent: None,
        host: "raw.githubusercontent.com",
        address: "185.199.108.133",
        method: "GET",
        target: "/some/gist/install.sh",
        status: 200,
        bytes: 3_200,
        rpc: None,
    },
    // The one that is worth noticing, which is the point of having a demonstration at all.
    Scene {
        process: "node",
        agent: Some("claude"),
        host: "0x0.st",
        address: "193.29.57.6",
        method: "POST",
        target: "/",
        status: 200,
        bytes: 54_800,
        rpc: None,
    },
];

/// Writes a demonstration into a database at `path`, which must not exist.
///
/// `hours` is how far back the afternoon reaches. Returns how many requests and connections were written.
pub fn write(path: &Path, now: i64, hours: i64) -> Result<(usize, usize)> {
    if path.exists() {
        bail!(
            "{} already exists. A demonstration is written to a new file, because the alternative is a \
             command that can overwrite a database holding real traffic.",
            path.display()
        );
    }
    let hours = hours.clamp(1, 72);
    let mut store = Store::open(path)?;
    store.mark_demonstration()?;

    let mut requests = 0;
    let mut connections = 0;
    // A generator rather than a dependency, and a fixed seed: the same arguments produce the same
    // database, so a screenshot can be retaken and a test can assert what is in one.
    let mut seed: u64 = 0x5eed_1337;
    let mut next = move || {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        (seed >> 33) as u32
    };

    let span = hours * 3_600;
    for round in 0..6 {
        for (index, scene) in SCENES.iter().enumerate() {
            let step = span / (6 * SCENES.len() as i64).max(1);
            let at = now - span + (round * SCENES.len() as i64 + index as i64) * step;
            let pid = 2_000 + (index as u32 * 7) + round as u32;
            store.record_connection(ConnectionRow {
                at,
                process: scene.process.to_owned(),
                confidence: "certain".to_owned(),
                pid,
                agent: scene.agent.map(str::to_owned),
                destination: Some(scene.address.to_owned()),
                port: 443,
                blocked: false,
            })?;
            connections += 1;
            let varied = scene.bytes / 2 + next() % scene.bytes.max(1);
            store.record_request(RequestRow {
                at,
                process: scene.process.to_owned(),
                confidence: "certain".to_owned(),
                pid,
                agent: scene.agent.map(str::to_owned),
                direction: "out".to_owned(),
                protocol: Some("http/2".to_owned()),
                method: Some(scene.method.to_owned()),
                target: Some(scene.target.to_owned()),
                host: Some(scene.host.to_owned()),
                status: Some(scene.status),
                bytes: varied,
                truncated: varied > 200_000,
                unreadable: None,
                rpc_method: scene.rpc.map(|(method, _)| method.to_owned()),
                rpc_tool: scene.rpc.and_then(|(_, tool)| tool.map(str::to_owned)),
            })?;
            requests += 1;
        }

        // Coverage, which is the screen that makes the rest trustworthy and therefore the screen a
        // demonstration must not leave empty. `gh` is written in Go: its TLS is linked into its own binary
        // and nothing can be read from it, which is exactly the case this states rather than hides.
        for step in 0..3 {
            store.record_connection(ConnectionRow {
                at: now - span + round * 600 + step * 41,
                process: "gh".to_owned(),
                confidence: "certain".to_owned(),
                pid: 3_100 + round as u32,
                agent: Some("claude".to_owned()),
                destination: Some("140.82.121.6".to_owned()),
                port: 443,
                blocked: false,
            })?;
            connections += 1;
        }
    }

    // And one connection a rule refused, because a demonstration with no rule in it is a demonstration of
    // half the program.
    store.record_connection(ConnectionRow {
        at: now - 900,
        process: "node".to_owned(),
        confidence: "certain".to_owned(),
        pid: 2_311,
        agent: Some("claude".to_owned()),
        destination: Some("169.254.169.254".to_owned()),
        port: 80,
        blocked: true,
    })?;
    connections += 1;
    store.put_rule(
        "block",
        "169.254.169.254",
        0,
        "everyone",
        Some("starter: metadata"),
    )?;
    store.flush()?;

    Ok((requests, connections))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Slice;

    /// A directory that is removed when the test ends, without a dependency for it.
    fn scratch(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("flowlight-demo-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a temporary directory");
        path
    }

    /// The point of the thing: something to photograph, on every screen that matters.
    #[test]
    fn a_demonstration_fills_every_screen_that_matters() {
        let directory = scratch("filled");
        let path = directory.join("demo.db");
        let (requests, connections) = write(&path, 1_700_000_000, 6).expect("a demonstration");
        assert!(requests > 40, "{requests}");
        assert!(connections > requests, "{connections} against {requests}");

        let mut store = Store::open(&path).expect("the database");
        assert!(store.is_demonstration().expect("the mark"));

        // Traffic, sliced every way a report can slice it.
        for slice in [Slice::Process, Slice::Host, Slice::Address, Slice::Protocol] {
            assert!(
                !store
                    .breakdown(slice, 0, 20, None)
                    .expect("a breakdown")
                    .is_empty(),
                "{} is empty",
                slice.as_str()
            );
        }

        // Coverage, which is the screen that makes the rest trustworthy: a demonstration that left it empty
        // would be a demonstration of a tool that never misses anything, which is not this one.
        let coverage = store.coverage(0).expect("coverage");
        assert!(coverage.requests > 0);
        assert!(
            coverage.unread.iter().any(|row| row.process == "gh"),
            "{:?}",
            coverage.unread
        );
        assert_eq!(coverage.refused, 1);

        // An agent, its children, and something said over MCP.
        let agents = store.agents(0).expect("agents");
        assert!(agents.iter().any(|row| row.agent == "claude"));
        assert!(
            store
                .requests_since(0, 200, None)
                .expect("requests")
                .iter()
                .any(|row| row.rpc_tool.as_deref() == Some("read_file"))
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// The same arguments, the same database. A screenshot that has to be retaken should be retakeable.
    #[test]
    fn the_same_arguments_produce_the_same_database() {
        let directory = scratch("same");
        let first = directory.join("one.db");
        let second = directory.join("two.db");
        write(&first, 1_700_000_000, 6).expect("one");
        write(&second, 1_700_000_000, 6).expect("two");

        let totals = |path: &std::path::Path| {
            let mut store = Store::open(path).expect("the database");
            store
                .breakdown(Slice::Host, 0, 50, None)
                .expect("a breakdown")
                .into_iter()
                .map(|share| (share.name, share.events, share.bytes))
                .collect::<Vec<_>>()
        };
        assert_eq!(totals(&first), totals(&second));

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// It will not write over anything. The path it is given may hold somebody's real history, and the way to
    /// be sure it is not overwritten is to refuse every file that already exists.
    #[test]
    fn a_demonstration_never_writes_over_a_file() {
        let directory = scratch("existing");
        let path = directory.join("already.db");
        std::fs::write(&path, b"not a demonstration").expect("a file");
        let refused = write(&path, 1_700_000_000, 6).expect_err("a refusal");
        assert!(
            format!("{refused:#}").contains("already exists"),
            "{refused:#}"
        );
        assert_eq!(
            std::fs::read(&path).expect("the file"),
            b"not a demonstration"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }
}
