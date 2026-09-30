//! English, which is the original.
//!
//! These are the sentences the rest of the program is tested against. A change here is a change to what
//! Flowlight says it does, which is why they read as complete sentences rather than as labels.

/// Every phrase, in the order it is read on a screen.
pub const PHRASES: &[(&str, &str)] = &[
    // The sentence a translation ends on. Nothing in English, where this is the tested wording.
    (
        "text.translated",
        "This text is a translation, and has not yet been checked by a native speaker. Flowlight is tested \
         against the English wording; where the two differ, the English is what the program does.",
    ),
    // Counted things.
    ("days.one", "{count} day"),
    ("days.many", "{count} days"),
    (
        "retention.describe",
        "keeping individual requests for {detail}, and a daily summary for {summary}",
    ),
    // The fields an exported record can carry, as a disclosure names them.
    ("field.at", "when"),
    ("field.process", "the process"),
    ("field.confidence", "how the process was named"),
    ("field.pid", "the process identifier"),
    ("field.agent", "the agent"),
    ("field.direction", "the direction"),
    ("field.host", "the host"),
    ("field.method", "the method"),
    ("field.target", "the path"),
    ("field.status", "the status"),
    ("field.bytes", "the size"),
    ("field.protocol", "the protocol"),
    ("field.rpc_method", "the MCP method"),
    ("field.rpc_tool", "the tool's name"),
    // Export: what leaves the machine, where it goes, and what does not.
    (
        "export.destination.none",
        "No destination has been set, so nothing can be sent anywhere.",
    ),
    (
        "export.destination.otlp",
        "Every request Flowlight reads will be sent over the network to {destination}, as OTLP.",
    ),
    (
        "export.destination.file",
        "Every request Flowlight reads will be written to {destination}, one line each. Nothing crosses the \
         network.",
    ),
    (
        "export.destination.unusable",
        "{destination} is neither a collector nor an absolute file path, so nothing can be sent to it.",
    ),
    (
        "export.fields.none",
        "No fields travel, which means each record would say nothing at all.",
    ),
    ("export.fields.one", "{count} field travels: {fields}."),
    ("export.fields.many", "{count} fields travel: {fields}."),
    ("export.withheld", "These do not: {fields}."),
    (
        "export.headers.one",
        "{count} header is sent with each batch: {names}. The values are not shown here and are not part of \
         what you are agreeing to.",
    ),
    (
        "export.headers.many",
        "{count} headers are sent with each batch: {names}. The values are not shown here and are not part of \
         what you are agreeing to.",
    ),
    (
        "export.bound",
        "This agreement is bound to exactly that. Changing the destination, the fields or the headers stops \
         the export until somebody agrees again.",
    ),
    ("export.why.off", "Export is off."),
    (
        "export.why.nowhere",
        "No destination has been set, so there is nowhere to send anything.",
    ),
    (
        "export.why.unusable",
        "The destination is neither an http:// or https:// collector nor an absolute file path, so it is not \
         clear what sending to it would mean.",
    ),
    (
        "export.why.unagreed",
        "Nobody has agreed to this yet. Nothing is sent until somebody does.",
    ),
    (
        "export.why.changed",
        "What is being sent, or where, has changed since somebody agreed to it. Nothing is sent until somebody \
         agrees to what it is now.",
    ),
    // Ask: a question about this machine's own traffic, answered by a model somebody configured.
    (
        "ask.none",
        "No model is configured, so questions cannot be answered. Flowlight for Linux has no model of its own: \
         there are no bundled weights, and no default pointing at somebody's API.",
    ),
    (
        "ask.remote",
        "Your question and the results of the queries Flowlight runs for it will be sent to {endpoint}.",
    ),
    (
        "ask.local",
        "Your question goes to {endpoint}, which is on this machine or this network. Nothing crosses the \
         internet.",
    ),
    (
        "ask.sent",
        "What is sent is the question, the instructions, and the totals and names that Flowlight's own queries \
         return. Never a row of history, never a request target, and never anything the model did not ask for.",
    ),
    (
        "ask.queries",
        "The model cannot see the database. It may name one of a fixed list of queries, which Flowlight runs; \
         there is no query language and no way to write one.",
    ),
    (
        "ask.recorded",
        "The connection to the provider is recorded and attributed to flowlightd, like any other process's. A \
         tool that hid its own traffic would have no business showing anybody else's.",
    ),
    (
        "ask.kind.local",
        "a model server on this machine or this network",
    ),
    ("ask.kind.compatible", "an OpenAI-compatible endpoint"),
    ("ask.kind.anthropic", "Anthropic"),
    ("ask.kind.gemini", "Google Gemini"),
    ("ask.safety.fine", "{endpoint} is fine."),
    ("ask.safety.not_a_url", "{endpoint} is not a URL."),
    (
        "ask.safety.wrong_scheme",
        "{endpoint} is neither an http:// nor an https:// address.",
    ),
    (
        "ask.safety.clear",
        "{endpoint} is plain http:// to an address that is not this machine or a private network. A key and a \
         question about this machine's own traffic would cross the network in the clear, so Flowlight will not \
         send them. Use https://.",
    ),
    // Interception: the one feature that changes what an application sees.
    (
        "intercept.watching",
        "Interception is not watching. Everything else Flowlight does reads what an application hands its TLS \
         library and changes nothing that crosses the network.",
    ),
    (
        "intercept.agents.none",
        "No agents are named, so nothing is redirected. Interception applies to the agents it names and to \
         nothing else on this machine.",
    ),
    (
        "intercept.agents",
        "Connections from {agents} — and from anything they start — are redirected to a proxy on this machine, \
         which terminates TLS and opens its own connection onwards.",
    ),
    (
        "intercept.authority",
        "That proxy presents a certificate signed by a certificate authority created on this machine. Anything \
         that does not trust it will refuse the connection, which is what a pinned certificate is supposed to \
         do.",
    ),
    (
        "intercept.passthrough",
        "A host nobody has written a mock for is passed through without being terminated at all, so the \
         certificate is only ever presented where there is a reason to.",
    ),
    (
        "intercept.never",
        "These are never terminated, whatever else says so: {hosts}.",
    ),
    (
        "intercept.off",
        "Turning it off stops the redirect immediately. Removing the certificate authority is a separate step, \
         because trusting one and untrusting it are both things somebody should do on purpose.",
    ),
    // Owners: asking who operates an address, over DNS.
    (
        "owners.what",
        "Flowlight will ask who operates the addresses this machine has connected to.",
    ),
    (
        "owners.question",
        "The question is a DNS lookup of Team Cymru's public routing data, sent to {resolver} — this machine's \
         own resolver, or a public one if it has none configured.",
    ),
    (
        "owners.sent",
        "What is sent is an address. Not which process reached it, not when, not how often, and nothing else \
         Flowlight knows about it.",
    ),
    (
        "owners.local",
        "An address on this machine or this network is never asked about: the answer is already known, and the \
         question would be about your network.",
    ),
    (
        "owners.rate",
        "Four addresses a minute at most, busiest first, and never the same one twice.",
    ),
    // Why nothing is happening, when nothing is.
    (
        "ask.why.off",
        "Ask is off. There is no model in Flowlight for Linux, so one has to be configured: `flowlightd model --kind local --model <name>` for a server on this machine, or a provider and a key.",
    ),
    (
        "ask.why.no_endpoint",
        "No endpoint is set, so there is nothing to ask.",
    ),
    (
        "ask.why.no_model",
        "No model name is set. Every provider needs to be told which model to use, and there is no sensible default to guess at.",
    ),
    (
        "ask.why.no_key",
        "{kind} needs a key, and there is not one on file.",
    ),
    ("ask.why.unconfigured", "Ask is not configured."),
    (
        "intercept.why.off",
        "Interception is off. Nothing is terminated, and no certificate of Flowlight's is presented to anything.",
    ),
    (
        "intercept.why.no_agents",
        "Interception is on and names no agents, so nothing is redirected. Naming one is how the scope is chosen: `flowlightd intercept --agent claude`.",
    ),
    ("owners.resolver.public", "a public resolver"),
    // What is captured and for how long, said at startup.
    (
        "budget.payloads.off",
        "Payloads are not read at all. Connections are still attributed.",
    ),
    (
        "budget.session.expired",
        "Payload capture has run out and is no longer reading anything. Renew it to start again.",
    ),
    (
        "budget.session.remaining",
        "Payloads are being read for another {remaining}.",
    ),
    (
        "budget.session.unlimited",
        "Payloads are being read, with no session limit — which was asked for, not assumed.",
    ),
    (
        "budget.daily.none",
        "There is no daily ceiling on how much one process may contribute.",
    ),
    (
        "budget.daily",
        "After {size} in a day, a process stops having its payloads captured until tomorrow.",
    ),
    (
        "budget.paths.full",
        "Request paths are kept in full, with credentials removed from them.",
    ),
    (
        "budget.paths.host",
        "Only the host of a request is kept, never the path it asked for.",
    ),
    (
        "budget.paths.none",
        "Neither paths nor query strings are kept. Hosts are, because nothing can be grouped without them.",
    ),
    (
        "budget.retention",
        "Individual requests are kept for {detail}, and a daily summary for {summary}.",
    ),
    ("time.seconds.one", "{count} second"),
    ("time.seconds.many", "{count} seconds"),
    ("time.minutes.one", "{count} minute"),
    ("time.minutes.many", "{count} minutes"),
    ("time.hours.one", "{count} hour"),
    ("time.hours.many", "{count} hours"),
    ("time.joined", "{hours} and {minutes}"),
    ("size.bytes", "{count} bytes"),
    // The channels that are not the network.
    (
        "devices.channels",
        "These are the channels that are not the network: what is plugged in over USB, what is paired over Bluetooth, and which removable volumes are mounted.",
    ),
    (
        "devices.no_bytes",
        "What is reported is what is connected and when that changed. Never how much went through any of it: Linux does not account for bytes per device in any way a process can be attributed, and a number nobody can stand behind is worse than no number.",
    ),
    (
        "devices.sources",
        "Everything is read from the files the kernel already publishes in /sys and /proc. Nothing is asked of a system service, and nothing leaves this machine.",
    ),
    (
        "devices.off",
        "Off until it is asked for — not because it needs a permission Flowlight does not have, but because it widens what is watched.",
    ),
];
