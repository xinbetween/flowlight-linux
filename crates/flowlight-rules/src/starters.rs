//! The rules people write first, written down.
//!
//! Every one of these is a rule somebody arrives at after watching an agent for a week: the addresses that
//! hand out credentials to whoever asks, the places a file can be put where a link is the only thing anybody
//! needs, the endpoints that post to somebody else's chat. Having them in a list does not make them right for
//! any particular machine — it makes them a thing you can read and decide about, rather than a thing you have
//! to think of.
//!
//! # Two invariants, both tested
//!
//! **Nothing here allows anything.** A starter that widens what is permitted would be a default somebody did
//! not choose, arriving under a friendly name. These block or ask; the tests refuse an `allow`.
//!
//! **Nothing here names anything at all.** A starter whose subject matched every host would be a switch for
//! turning the network off, and it would be applied by somebody who read the name and not the list.
//!
//! # Ask rather than block, where a person might reasonably be doing it
//!
//! Pasting a log into a pastebin is a normal thing for a person to do and an alarming thing for an agent to
//! do, and a rule cannot tell them apart. So most of these ask, which is the action that exists for exactly
//! that case. The metadata service is the exception: nothing an agent legitimately does involves asking a
//! link-local address for this machine's cloud credentials.

use crate::Action;

/// A rule, or a handful of them, somebody might want before they want anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Starter {
    /// What to call it, on a command line.
    pub id: &'static str,
    /// What it does.
    pub action: Action,
    /// Why somebody would want it, in one sentence that says what goes wrong without it.
    pub why: &'static str,
    /// The hosts and addresses it is about.
    pub subjects: &'static [&'static str],
}

/// Every starter, in the order they are offered.
///
/// Ordered by how little argument there is about them: the first is a rule with no legitimate exception, and
/// the last is a rule that depends on what the machine is for.
pub const EVERY_STARTER: &[Starter] = &[
    Starter {
        id: "metadata",
        action: Action::Block,
        why: "A cloud instance metadata service hands out this machine's credentials to whatever asks it \
               from this machine, with no authentication of any kind. Nothing an agent legitimately does \
               involves asking one.",
        subjects: &[
            "169.254.169.254",
            "metadata.google.internal",
            "169.254.170.2",
            "fd00:ec2::254",
        ],
    },
    Starter {
        id: "pastebins",
        action: Action::Ask,
        why: "A place to put a file where a link is the only thing anybody needs to read it. Pasting a log \
               there is a normal thing for a person to do and an odd thing for an agent to do, and only one \
               of you can tell the difference.",
        subjects: &[
            "pastebin.com",
            "paste.ee",
            "0x0.st",
            "transfer.sh",
            "file.io",
            "bashupload.com",
            "termbin.com",
            "dpaste.org",
        ],
    },
    Starter {
        id: "webhooks",
        action: Action::Ask,
        why: "An endpoint that posts into somebody's chat or channel. An agent that can reach one can send \
               anything it has read to an audience you did not choose, in one request, with no reply to \
               notice.",
        subjects: &[
            "hooks.slack.com",
            "discord.com",
            "discordapp.com",
            "api.telegram.org",
            "webhook.site",
            "*.webhook.site",
        ],
    },
    Starter {
        id: "doh",
        action: Action::Ask,
        why: "DNS over HTTPS resolves names somewhere this machine's own resolver never sees, which means \
               Flowlight records a connection to an address and cannot say which name was asked for. It is \
               the one thing that makes the rest of this less useful.",
        subjects: &[
            "cloudflare-dns.com",
            "dns.google",
            "dns.quad9.net",
            "doh.opendns.com",
            "mozilla.cloudflare-dns.com",
        ],
    },
    Starter {
        id: "tunnels",
        action: Action::Ask,
        why: "A tunnel makes something on this machine reachable from outside it, without anything being \
               opened on your network. That is the point of them, and it is worth being asked about rather \
               than finding out.",
        subjects: &[
            "*.ngrok.io",
            "*.ngrok-free.app",
            "*.ngrok.app",
            "*.trycloudflare.com",
            "*.loca.lt",
            "*.serveo.net",
            "*.localhost.run",
        ],
    },
];

/// One starter by name.
pub fn starter(id: &str) -> Option<&'static Starter> {
    let wanted = id.trim().to_lowercase();
    EVERY_STARTER
        .iter()
        .find(|candidate| candidate.id == wanted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Subject;
    use alloc::vec::Vec;

    /// A starter that allows something is a default somebody did not choose, arriving under a friendly name.
    #[test]
    fn no_starter_allows_anything() {
        for starter in EVERY_STARTER {
            assert_ne!(starter.action, Action::Allow, "{}", starter.id);
        }
    }

    /// And a starter that names anything at all is a switch for turning the network off, applied by somebody who
    /// read the name rather than the list.
    #[test]
    fn no_starter_names_everything() {
        for starter in EVERY_STARTER {
            for subject in starter.subjects {
                assert_ne!(
                    Subject::parse(subject),
                    Subject::Anything,
                    "{} names {subject}",
                    starter.id
                );
                assert!(!subject.is_empty(), "{} has an empty subject", starter.id);
                assert_eq!(
                    *subject,
                    subject.trim().to_lowercase().as_str(),
                    "{} writes {subject} in a way a rule would not match",
                    starter.id
                );
            }
        }
    }

    /// Every one of them says why, in a sentence rather than a label. A list of hosts with no reasons is a
    /// list somebody applies without deciding anything.
    #[test]
    fn every_starter_says_why() {
        for starter in EVERY_STARTER {
            assert!(starter.why.len() > 60, "{} does not say why", starter.id);
            assert!(!starter.subjects.is_empty(), "{} names nothing", starter.id);
        }
    }

    #[test]
    fn a_starter_is_found_by_name_however_it_is_written() {
        assert_eq!(starter("metadata").map(|it| it.id), Some("metadata"));
        assert_eq!(starter("  METADATA ").map(|it| it.id), Some("metadata"));
        assert!(starter("nothing-like-this").is_none());
    }

    #[test]
    fn no_two_starters_share_a_name() {
        let mut names: Vec<&str> = EVERY_STARTER.iter().map(|it| it.id).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(before, names.len());
    }
}
