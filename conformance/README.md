# Conformance

Rule semantics as data, so that two implementations of "block" cannot quietly come to mean different things.

[xinbetween/flowlight](https://github.com/xinbetween/flowlight) is the macOS application, in Swift.
[xinbetween/flowlight-linux](https://github.com/xinbetween/flowlight-linux) is this one, in Rust. They share no
code. What must not diverge is not code but **semantics**: what `block` means against `allow`, how precedence
resolves, what a pattern covers. Those are decisions, and a decision written down in two languages is a decision
that will be made twice and eventually differently.

So the cases live here, in JSON, and each implementation loads the same file. A divergence is a failing test
rather than a support thread eighteen months later.

## The files

- `rules.json` — deciding what happens to a connection. Given a set of rules and a set of facts, which action
  wins and which rule produced it.

## The shape

```json
{
  "version": 1,
  "cases": [
    {
      "name": "what this case is about",
      "why": "why the answer is what it is, for whoever reads a failure",
      "rules": [{ "id": 1, "action": "block", "subject": "example.com", "port": 0, "scope": "everyone" }],
      "facts": { "host": "example.com", "address": null, "port": 443, "agent": null },
      "expect": { "action": "block", "rule": 1 }
    }
  ]
}
```

Every field is required and there are no defaults, deliberately: a case that leaves something out is a case
whose author and reader disagree about what it says.

- `action` is `allow`, `ask` or `block`.
- `subject` is a host, `*.a-domain`, a literal address, or `*` for anything.
- `port` is `0` for every port.
- `scope` is `everyone` or `agent:<name>`.
- `expect.rule` is the identifier of the rule that decided, or `null` when nothing matched and the default
  applied.

## Running them

Here: `cargo test -p flowlight-rules --test conformance`, which is part of CI.

On macOS: load the same file and assert the same answers. The file is the contract; how each side reaches it is
its own business.

## Adding a case

When a question about semantics comes up, the answer goes here first and into the code second. That ordering is
the point — otherwise the code is the specification, and there are two of them.
