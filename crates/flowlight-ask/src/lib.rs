//! Asking Flowlight a question about this machine, with a model somebody else configured.
//!
//! macOS has a model the operating system provides. Linux does not, and this crate does not carry one: there
//! are no bundled weights and no default endpoint pointing at somebody's API. Until a model is configured the
//! feature is off and says so.
//!
//! # What a model is and is not given
//!
//! It is given the question, a set of instructions, and the results of queries it names from a fixed list. It
//! is not given the database, a table, or a query language — [`query::Query`] is the whole surface, and every
//! one of those queries returns counts, totals and names rather than rows. The boundary is a type, not a
//! promise: there is no way to express "run this SQL" in the shape a provider is handed.
//!
//! # Where the pieces are
//!
//! - [`query`] — the list, the schema and the instructions. The privacy boundary.
//! - [`runner`] — running those queries against [`flowlight_store`].
//! - [`provider`] — the three wire shapes, and the loop that lets a model call queries before it answers.
//! - [`window`] — reading a time window out of what the model wrote.
//! - [`guide`] — Flowlight's own written-down answer to "how do I…", so a model never invents a flag.

pub mod guide;
pub mod provider;
pub mod query;
pub mod runner;
pub mod window;

pub use provider::{Answered, Question, Ran};
pub use query::{Call, Query};

use anyhow::Result;
use flowlight_store::{Ask, Store};

/// Asks the configured model a question, running whatever queries it names against the store.
///
/// The one function anything outside this crate needs. `now` is passed in rather than read, so that a test and
/// a smoke test can both be about a known moment.
pub fn answer(
    configuration: &Ask,
    key: &str,
    asked: &str,
    store: &mut Store,
    now: i64,
    clock: &str,
) -> Result<Answered> {
    let question = Question {
        question: asked.to_owned(),
        instructions: query::instructions(clock),
    };
    provider::ask(
        configuration,
        key,
        &question,
        &mut |call| runner::run(call, store, now).map(|produced| produced.json),
        // Nothing to show it to from here. The daemon passes a closure that prints it; this is the path a
        // socket takes, where the bodies come back in the answer instead.
        &mut |_| {},
    )
}
