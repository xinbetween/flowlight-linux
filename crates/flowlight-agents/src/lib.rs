//! Which agent a process is working for, and what that agent was configured to talk to.
//!
//! Everything else in Flowlight is about processes. This is about the layer above them, which is the one
//! people actually think in: `claude` does not make requests, it spawns `node`, which spawns `git`, which
//! spawns `git-remote-https`, which makes the request. Attributing that to `git-remote-https` is true and
//! useless.
//!
//! Two halves, and they answer different questions.
//!
//! - [`ancestry`] — **who is this working for?** Walked up the process tree, so a request from anything an
//!   agent started is attributed to the agent, however many shells deep.
//! - [`mcp`] — **what was it told it could talk to?** Read out of the agent's own configuration files, so
//!   that what an agent *reached* can be compared with what it was *given*. The gap in either direction is
//!   the interesting part: a server configured and never used is clutter, and a host reached that is in no
//!   configuration is the thing worth a second look.
//! - [`wire`] — **what did it actually say?** MCP is JSON-RPC, so the method and the name of the tool are
//!   in plaintext a uprobe has already copied. Never the arguments.
//! - [`workspace`] — **what is it set up to do?** Skills, subagents, commands, hooks, permissions and
//!   plugins, read out of the same files [`mcp`] reads. A hook is a program the agent runs on its own behalf
//!   and a permission is a decision somebody made once, and neither is visible from any amount of watching
//!   the network.
//! - [`launch`] — **what does it need to be started with?** Which variables an agent reads at launch and
//!   nowhere else, and what to call an agent somebody is starting. The forking lives in the daemon; the
//!   deciding lives here.
//!
//! No Linux-only dependency, so it builds and its tests run anywhere — the same reason `flowlight-common`
//! and `flowlight-store` are crates of their own. The `/proc` walking that feeds [`ancestry`] lives in the
//! daemon; the deciding lives here, where it can be tested against a process tree written out by hand.

pub mod ancestry;
pub mod launch;
pub mod mcp;
pub mod wire;
pub mod workspace;
