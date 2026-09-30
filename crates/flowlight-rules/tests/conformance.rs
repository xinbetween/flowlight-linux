//! The shared cases, run against this implementation.
//!
//! `conformance/rules.json` is the contract between this and the macOS build. It is loaded rather than
//! transcribed: a case copied into Rust is a case that can be copied wrong, and then the two implementations
//! agree about a file neither of them reads.
//!
//! A failure here is not a broken test. It is two implementations of "block" that have come to mean different
//! things, which is the thing this exists to catch.

use flowlight_rules::{Action, Facts, Rule, Scope, Subject, decide};
use serde::Deserialize;

/// The file, as it is written.
#[derive(Debug, Deserialize)]
struct Suite {
    version: u32,
    cases: Vec<Case>,
}

/// One question and its answer.
#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    why: String,
    rules: Vec<Written>,
    facts: Given,
    expect: Expected,
}

/// A rule as the file writes one.
#[derive(Debug, Deserialize)]
struct Written {
    id: i64,
    action: String,
    subject: String,
    port: u16,
    scope: String,
}

/// The facts as the file writes them. Every field is present, including the ones that are null.
#[derive(Debug, Deserialize)]
struct Given {
    host: Option<String>,
    address: Option<String>,
    port: Option<u16>,
    agent: Option<String>,
}

/// What is supposed to happen.
#[derive(Debug, Deserialize)]
struct Expected {
    action: String,
    rule: Option<i64>,
}

/// Every case in the file.
#[test]
fn the_shared_cases_hold() {
    let text = std::fs::read_to_string(path()).expect("conformance/rules.json should be readable");
    let suite: Suite = serde_json::from_str(&text).expect("conformance/rules.json should be JSON");
    assert_eq!(suite.version, 1, "this runner understands version 1");
    assert!(
        suite.cases.len() >= 30,
        "the suite has shrunk to {} cases; semantics are not usually deleted",
        suite.cases.len()
    );

    let mut wrong = Vec::new();
    for case in &suite.cases {
        let rules: Vec<Rule> = case
            .rules
            .iter()
            .map(|written| Rule {
                id: written.id,
                action: Action::parse(&written.action)
                    .unwrap_or_else(|| panic!("`{}` is not an action", written.action)),
                subject: Subject::parse(&written.subject),
                // Zero in the file means every port, which is how the database writes it too; the rule
                // model says the same thing with `None`.
                port: (written.port != 0).then_some(written.port),
                scope: Scope::parse(&written.scope)
                    .unwrap_or_else(|| panic!("`{}` is not a scope", written.scope)),
            })
            .collect();
        let facts = Facts {
            agent: case.facts.agent.clone(),
            host: case.facts.host.clone(),
            address: case.facts.address.clone(),
            port: case.facts.port,
        };
        let verdict = decide(&facts, &rules);
        let wanted = Action::parse(&case.expect.action)
            .unwrap_or_else(|| panic!("`{}` is not an action", case.expect.action));

        if verdict.action != wanted || verdict.rule != case.expect.rule {
            // Collected rather than asserted one at a time. When semantics move, several cases move together,
            // and knowing which ones is the whole diagnosis.
            wrong.push(format!(
                "  {}\n    expected {} by {:?}, got {} by {:?}\n    {}",
                case.name,
                wanted.as_str(),
                case.expect.rule,
                verdict.action.as_str(),
                verdict.rule,
                case.why
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "{} of {} shared cases disagree with this implementation.\n\n{}\n\nThese are the cases the macOS \
         build runs too. A failure here is two implementations of the same word meaning different things.",
        wrong.len(),
        suite.cases.len(),
        wrong.join("\n\n")
    );
}

/// Every case says what it is about and why, because a failure is read by somebody who did not write it.
#[test]
fn every_case_explains_itself() {
    let text = std::fs::read_to_string(path()).expect("conformance/rules.json should be readable");
    let suite: Suite = serde_json::from_str(&text).expect("conformance/rules.json should be JSON");
    for case in &suite.cases {
        assert!(!case.name.trim().is_empty(), "a case has no name");
        assert!(
            case.why.trim().len() > 20,
            "`{}` does not say why its answer is what it is",
            case.name
        );
    }
    // And no two cases share a name, or a failure names something ambiguous.
    let mut names: Vec<&str> = suite.cases.iter().map(|case| case.name.as_str()).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "two cases share a name");
}

/// Where the file is, from wherever the test happens to be run.
fn path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/rules.json")
        .canonicalize()
        .expect("the conformance directory should be beside the crates")
}
