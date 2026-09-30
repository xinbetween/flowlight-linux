//! Asking a model, wherever it is.
//!
//! The three request shapes are written out rather than abstracted into one, because they genuinely differ and
//! a wrong guess shows up as a model that silently stops calling tools. What they share is the part that
//! matters: the only thing that ever leaves is the question, the instructions, and the results of queries
//! Flowlight ran — and every body goes through `sending` first, so it can be shown before it goes.

use crate::query::{self, Call, Query, TOOL, TOOL_SUMMARY};
use anyhow::{Context as _, Result, bail};
use flowlight_store::ask::{Ask, Kind, Safety};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// How many times the model may call queries before it has to answer.
///
/// A model that keeps asking is usually lost, and an unbounded loop against somebody's paid API is not a
/// thing to ship.
pub const MOST_ROUNDS: usize = 6;

/// How long to wait for a model. Longer than anything else here: a local model on a laptop thinks slowly.
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(180);

/// What a model is asked.
pub struct Question {
    /// What somebody typed.
    pub question: String,
    /// The instructions every provider is given.
    pub instructions: String,
}

/// What came back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Answered {
    /// The answer, in sentences.
    pub answer: String,
    /// Which queries ran, and what each produced, for the transcript.
    pub calls: Vec<Ran>,
    /// The exact bodies that left this machine, if any did.
    pub sent: Vec<String>,
}

/// One query the model asked for, and what came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    /// Which query, as the model named it.
    pub query: String,
    /// What it said to fill in.
    pub arguments: BTreeMap<String, String>,
    /// The sentence describing the result.
    pub summary: String,
    /// Whether the call failed, and the model was told so.
    pub failed: bool,
}

/// What Flowlight does when the model names a query: runs it, or explains why it could not.
///
/// A closure rather than a trait, because there is exactly one implementation — the database — and the reason
/// it is behind anything at all is so a test can answer without one.
pub type Running<'a> = &'a mut dyn FnMut(&Call) -> Result<String>;

/// Somewhere to show a body before it goes.
pub type Sending<'a> = &'a mut dyn FnMut(&str);

/// Asks the configured model, and returns what it said.
pub fn ask(
    configuration: &Ask,
    key: &str,
    question: &Question,
    run: Running<'_>,
    sending: Sending<'_>,
) -> Result<Answered> {
    let endpoint = configuration
        .endpoint
        .as_deref()
        .context("no endpoint is configured, so there is nothing to ask")?;
    let model = configuration
        .model
        .as_deref()
        .context("no model is configured; every provider has to be told which model to use")?;
    // Checked here as well as when the endpoint was written, because a check that only exists at the place
    // something is configured is a check the next caller does not get.
    match Safety::of(endpoint, configuration.kind) {
        Safety::Fine => {}
        refused => bail!("{}", refused.describe(endpoint)),
    }
    if configuration.kind.needs_key() && key.trim().is_empty() {
        bail!(
            "{} needs a key and there is not one on file.",
            configuration.kind.described()
        );
    }

    let wire = Wire {
        kind: configuration.kind,
        endpoint: endpoint.to_owned(),
        model: model.to_owned(),
        key: key.trim().to_owned(),
    };
    match configuration.kind {
        Kind::Anthropic => wire.anthropic(question, run, sending),
        Kind::Gemini => wire.gemini(question, run, sending),
        Kind::Local | Kind::Compatible => wire.chat_completions(question, run, sending),
    }
}

/// What every shape needs to make a request.
struct Wire {
    kind: Kind,
    endpoint: String,
    model: String,
    key: String,
}

/// What to say when the model would not stop asking.
fn out_of_rounds() -> Answered {
    Answered {
        answer: "I ran out of steps before I could answer that. Try asking something narrower."
            .to_owned(),
        ..Answered::default()
    }
}

impl Wire {
    // MARK: OpenAI chat completions — also Ollama, LM Studio and anything compatible

    fn chat_completions(
        &self,
        question: &Question,
        run: Running<'_>,
        sending: Sending<'_>,
    ) -> Result<Answered> {
        let mut messages = vec![
            json!({ "role": "system", "content": question.instructions }),
            json!({ "role": "user", "content": question.question }),
        ];
        let mut answered = Answered::default();
        for _ in 0..MOST_ROUNDS {
            let body = json!({
                "model": self.model,
                "messages": messages,
                "tools": [{
                    "type": "function",
                    "function": {
                        "name": TOOL,
                        "description": TOOL_SUMMARY,
                        "parameters": query::schema(),
                    },
                }],
                "tool_choice": "auto",
                "stream": false,
            });
            let reply = self.post(&self.endpoint, &body, &mut answered, &mut *sending)?;
            let message = reply
                .pointer("/choices/0/message")
                .context("the provider's answer had no message in it")?;
            let calls = message
                .get("tool_calls")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if calls.is_empty() {
                answered.answer = cleaned(
                    message
                        .get("content")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                );
                return Ok(answered);
            }
            messages.push(message.clone());
            for call in &calls {
                let name = call
                    .pointer("/function/name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let arguments = call
                    .pointer("/function/arguments")
                    .and_then(Value::as_str)
                    .unwrap_or("{}");
                let output = self.perform(name, arguments, &mut *run, &mut answered);
                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": call.get("id").and_then(Value::as_str).unwrap_or_default(),
                    "content": output,
                }));
            }
        }
        Ok(Answered {
            calls: answered.calls,
            sent: answered.sent,
            ..out_of_rounds()
        })
    }

    // MARK: Anthropic messages

    fn anthropic(
        &self,
        question: &Question,
        run: Running<'_>,
        sending: Sending<'_>,
    ) -> Result<Answered> {
        let mut messages = vec![json!({ "role": "user", "content": question.question })];
        let mut answered = Answered::default();
        for _ in 0..MOST_ROUNDS {
            let body = json!({
                "model": self.model,
                "max_tokens": 1024,
                "system": question.instructions,
                "messages": messages,
                "tools": [{
                    "name": TOOL,
                    "description": TOOL_SUMMARY,
                    "input_schema": query::schema(),
                }],
            });
            let reply = self.post(&self.endpoint, &body, &mut answered, &mut *sending)?;
            let content = reply
                .get("content")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let uses: Vec<&Value> = content
                .iter()
                .filter(|part| part.get("type").and_then(Value::as_str) == Some("tool_use"))
                .collect();
            if uses.is_empty() {
                let text: Vec<&str> = content
                    .iter()
                    .filter_map(|part| part.get("text").and_then(Value::as_str))
                    .collect();
                answered.answer = cleaned(&text.join("\n"));
                return Ok(answered);
            }
            let mut results = Vec::new();
            for use_of_tool in &uses {
                let name = use_of_tool
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let arguments = serde_json::to_string(
                    use_of_tool
                        .get("input")
                        .unwrap_or(&Value::Object(Map::new())),
                )
                .unwrap_or_else(|_| "{}".to_owned());
                let output = self.perform(name, &arguments, &mut *run, &mut answered);
                results.push(json!({
                    "type": "tool_result",
                    "tool_use_id": use_of_tool.get("id").and_then(Value::as_str).unwrap_or_default(),
                    "content": output,
                }));
            }
            messages.push(json!({ "role": "assistant", "content": content }));
            messages.push(json!({ "role": "user", "content": results }));
        }
        Ok(Answered {
            calls: answered.calls,
            sent: answered.sent,
            ..out_of_rounds()
        })
    }

    // MARK: Gemini

    fn gemini(
        &self,
        question: &Question,
        run: Running<'_>,
        sending: Sending<'_>,
    ) -> Result<Answered> {
        // The model is part of the path here, not the body.
        let separator = if self.endpoint.ends_with('/') {
            ""
        } else {
            "/"
        };
        let target = format!("{}{separator}{}:generateContent", self.endpoint, self.model);
        let mut contents = vec![json!({
            "role": "user",
            "parts": [{ "text": question.question }],
        })];
        let mut answered = Answered::default();
        for _ in 0..MOST_ROUNDS {
            let body = json!({
                "systemInstruction": { "parts": [{ "text": question.instructions }] },
                "contents": contents,
                "tools": [{ "functionDeclarations": [{
                    "name": TOOL,
                    "description": TOOL_SUMMARY,
                    "parameters": query::schema(),
                }]}],
            });
            let reply = self.post(&target, &body, &mut answered, &mut *sending)?;
            let content = reply
                .pointer("/candidates/0/content")
                .context("the provider's answer had no candidate in it")?
                .clone();
            let parts = content
                .get("parts")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let calls: Vec<&Value> = parts
                .iter()
                .filter_map(|part| part.get("functionCall"))
                .collect();
            if calls.is_empty() {
                let text: Vec<&str> = parts
                    .iter()
                    .filter_map(|part| part.get("text").and_then(Value::as_str))
                    .collect();
                answered.answer = cleaned(&text.join("\n"));
                return Ok(answered);
            }
            let mut responses = Vec::new();
            for call in &calls {
                let name = call.get("name").and_then(Value::as_str).unwrap_or_default();
                let arguments =
                    serde_json::to_string(call.get("args").unwrap_or(&Value::Object(Map::new())))
                        .unwrap_or_else(|_| "{}".to_owned());
                let output = self.perform(name, &arguments, &mut *run, &mut answered);
                responses.push(json!({
                    "functionResponse": {
                        "name": if name.is_empty() { TOOL } else { name },
                        "response": { "result": output },
                    },
                }));
            }
            contents.push(content);
            contents.push(json!({ "role": "user", "parts": responses }));
        }
        Ok(Answered {
            calls: answered.calls,
            sent: answered.sent,
            ..out_of_rounds()
        })
    }

    // MARK: Shared

    /// Turns whatever the model wrote into a call, or into a sentence explaining why it was not one.
    ///
    /// Every failure here comes back as words. A model handed an empty object concludes nothing happened; a
    /// model handed "there is no query called that, the ones that exist are …" names one that does.
    fn perform(
        &self,
        name: &str,
        arguments: &str,
        run: Running<'_>,
        answered: &mut Answered,
    ) -> String {
        if name != TOOL {
            let refusal = format!("There is no tool called '{name}'. The only one is {TOOL}.");
            answered.calls.push(Ran {
                query: name.to_owned(),
                arguments: BTreeMap::new(),
                summary: refusal.clone(),
                failed: true,
            });
            return refusal;
        }
        let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(arguments) else {
            let refusal = "Those arguments were not a JSON object.".to_owned();
            answered.calls.push(Ran {
                query: TOOL.to_owned(),
                arguments: BTreeMap::new(),
                summary: refusal.clone(),
                failed: true,
            });
            return refusal;
        };
        let named = fields
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let Some(query) = Query::parse(named) else {
            let names: Vec<&str> = query::EVERY_QUERY
                .iter()
                .map(|query| query.as_str())
                .collect();
            let refusal = format!(
                "There is no query called '{named}'. The ones that exist are: {}.",
                names.join(", ")
            );
            answered.calls.push(Ran {
                query: named.to_owned(),
                arguments: BTreeMap::new(),
                summary: refusal.clone(),
                failed: true,
            });
            return refusal;
        };
        // Everything but the query name, as strings. A number written as a number is still an argument:
        // models write `limit: 5` about as often as `limit: "5"`, and dropping it silently halves the answer.
        let mut given = BTreeMap::new();
        for (key, value) in &fields {
            if key == "query" {
                continue;
            }
            let text = match value {
                Value::String(text) => text.clone(),
                Value::Number(number) => number.to_string(),
                Value::Bool(flag) => flag.to_string(),
                _ => continue,
            };
            if !text.is_empty() {
                given.insert(key.clone(), text);
            }
        }
        let call = Call {
            query,
            arguments: given.clone(),
        };
        match run(&call) {
            Ok(output) => {
                answered.calls.push(Ran {
                    query: query.as_str().to_owned(),
                    arguments: given,
                    summary: String::new(),
                    failed: false,
                });
                output
            }
            // A failure comes back as words. A model handed an empty object concludes nothing happened; a
            // model handed a sentence writes a query it can.
            Err(err) => {
                let refusal = format!("{err:#}");
                answered.calls.push(Ran {
                    query: query.as_str().to_owned(),
                    arguments: given,
                    summary: refusal.clone(),
                    failed: true,
                });
                refusal
            }
        }
    }

    /// Posts one body and reads the JSON back.
    fn post(
        &self,
        url: &str,
        body: &Value,
        answered: &mut Answered,
        sending: Sending<'_>,
    ) -> Result<Value> {
        let text = serde_json::to_string_pretty(body)?;
        // Every time, here, rather than anywhere it could be forgotten. This is the whole basis for trusting
        // the feature.
        sending(&text);
        if self.kind.sends_off_the_machine() {
            answered.sent.push(text.clone());
        }
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(PATIENCE))
            .build()
            .new_agent();
        let mut request = agent.post(url).header("content-type", "application/json");
        for (name, value) in self.headers() {
            request = request.header(name, &value);
        }
        let mut response = match request.send(&text) {
            Ok(response) => response,
            Err(err) => {
                return Err(anyhow::Error::new(err)).with_context(|| {
                    format!(
                        "asking {url}. A model server that is not running is the commonest reason; \
                         `flowlightd model` says what is configured."
                    )
                });
            }
        };
        let status = response.status().as_u16();
        let read = response
            .body_mut()
            .read_to_string()
            .unwrap_or_else(|_| String::new());
        if !(200..300).contains(&status) {
            bail!("{}", explain(status, &read, url));
        }
        serde_json::from_str(&read).with_context(|| {
            format!(
                "reading {url}'s answer, which was not JSON: {}",
                first(&read, 200)
            )
        })
    }

    /// The headers each provider wants its key in.
    fn headers(&self) -> Vec<(&'static str, String)> {
        if self.key.is_empty() {
            return Vec::new();
        }
        match self.kind {
            Kind::Anthropic => vec![
                ("x-api-key", self.key.clone()),
                ("anthropic-version", "2023-06-01".to_owned()),
            ],
            Kind::Gemini => vec![("x-goog-api-key", self.key.clone())],
            Kind::Local | Kind::Compatible => {
                vec![("authorization", format!("Bearer {}", self.key))]
            }
        }
    }
}

/// What an HTTP failure means, in words somebody can act on.
fn explain(status: u16, body: &str, url: &str) -> String {
    match status {
        401 | 403 => format!("{url} rejected the key (HTTP {status})."),
        404 => format!(
            "Nothing answered at {url} (HTTP 404). Check the endpoint and the model name — a model that is \
             not installed on a local server looks exactly like this."
        ),
        429 => format!("{url} is rate-limiting this (HTTP 429)."),
        _ => format!("{url} answered HTTP {status}. {}", first(body, 200)),
    }
}

/// The first so many characters of something that might be enormous.
fn first(text: &str, many: usize) -> String {
    text.chars().take(many).collect()
}

/// Cleaning up after a model that answers with its own plumbing.
///
/// A small model sometimes prints the tool call it meant to make instead of making it. That is not an answer,
/// and showing it teaches people the feature is broken rather than that one reply went wrong.
pub fn cleaned(raw: &str) -> String {
    let mut text = raw.to_owned();
    for marker in [
        "<executable_end>",
        "<executable_start>",
        "<|eot_id|>",
        "<|end|>",
        "<end_of_turn>",
    ] {
        text = text.replace(marker, "");
    }
    let kept: Vec<&str> = text
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.starts_with("```") && !is_a_tool_call(trimmed)
        })
        .collect();
    let answer = kept.join("\n").replace("\n\n\n", "\n\n").trim().to_owned();
    if answer.is_empty() {
        return "The model replied with a tool call instead of an answer. The queries it ran are listed \
                below — ask again, or word the question a little differently."
            .to_owned();
    }
    answer
}

/// Whether a line is the model narrating a call rather than answering.
fn is_a_tool_call(line: &str) -> bool {
    let lowered = line.to_lowercase();
    let looks_like_one = lowered.contains("\"name\"")
        || lowered.starts_with("system tools")
        || lowered.starts_with("tool_call");
    looks_like_one
        && (lowered.contains("\"arguments\"")
            || lowered.starts_with("system tools")
            || lowered.starts_with("tool_call"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured(kind: Kind, endpoint: &str) -> Ask {
        Ask {
            enabled: true,
            kind,
            endpoint: Some(endpoint.to_owned()),
            model: Some("a-model".to_owned()),
        }
    }

    fn question() -> Question {
        Question {
            question: "what happened?".to_owned(),
            instructions: "answer it".to_owned(),
        }
    }

    /// Nothing is attempted against an endpoint a key must not cross. Refused before the socket is opened,
    /// so there is no version of this that sends first and checks second.
    #[test]
    fn a_clear_endpoint_is_refused_before_anything_is_sent() {
        let mut sent = Vec::new();
        let failed = ask(
            &configured(
                Kind::Compatible,
                "http://somebody.example/v1/chat/completions",
            ),
            "a-key",
            &question(),
            &mut |_| Ok("{}".to_owned()),
            &mut |body| sent.push(body.to_owned()),
        );
        assert!(failed.is_err());
        assert!(sent.is_empty(), "something was sent to an http:// endpoint");
    }

    #[test]
    fn a_hosted_provider_with_no_key_is_refused_before_anything_is_sent() {
        let mut sent = Vec::new();
        let failed = ask(
            &configured(Kind::Anthropic, "https://api.anthropic.com/v1/messages"),
            "   ",
            &question(),
            &mut |_| Ok("{}".to_owned()),
            &mut |body| sent.push(body.to_owned()),
        );
        assert!(failed.is_err());
        assert!(sent.is_empty());
    }

    #[test]
    fn a_provider_with_no_model_named_is_refused() {
        let mut configuration = configured(Kind::Local, "http://127.0.0.1:1/v1/chat/completions");
        configuration.model = None;
        assert!(
            ask(
                &configuration,
                "",
                &question(),
                &mut |_| Ok("{}".to_owned()),
                &mut |_| {}
            )
            .is_err()
        );
    }

    /// A key goes in the header each provider expects, and nowhere else.
    #[test]
    fn a_key_goes_in_the_header_its_provider_wants() {
        let wire = |kind: Kind| Wire {
            kind,
            endpoint: "https://x.example".to_owned(),
            model: "m".to_owned(),
            key: "sekrit".to_owned(),
        };
        assert_eq!(
            wire(Kind::Anthropic)
                .headers()
                .first()
                .map(|(name, _)| *name),
            Some("x-api-key")
        );
        assert_eq!(
            wire(Kind::Gemini).headers().first().map(|(name, _)| *name),
            Some("x-goog-api-key")
        );
        assert_eq!(
            wire(Kind::Compatible)
                .headers()
                .first()
                .map(|(name, _)| *name),
            Some("authorization")
        );
        // And a local server with no key gets no header at all, rather than `Bearer `.
        let bare = Wire {
            key: String::new(),
            ..wire(Kind::Local)
        };
        assert!(bare.headers().is_empty());
    }

    /// A model that names a query nobody wrote is told which ones exist, rather than handed an empty result
    /// it will report as "nothing happened".
    #[test]
    fn a_query_that_does_not_exist_comes_back_as_a_sentence() {
        let wire = Wire {
            kind: Kind::Local,
            endpoint: String::new(),
            model: String::new(),
            key: String::new(),
        };
        let mut answered = Answered::default();
        let output = wire.perform(
            TOOL,
            r#"{"query":"SELECT * FROM requests"}"#,
            &mut |_| Ok("{}".to_owned()),
            &mut answered,
        );
        assert!(output.contains("There is no query called"), "{output}");
        assert!(output.contains("topHosts"), "{output}");
        assert!(answered.calls.first().is_some_and(|ran| ran.failed));
    }

    #[test]
    fn a_tool_that_does_not_exist_comes_back_as_a_sentence_too() {
        let wire = Wire {
            kind: Kind::Local,
            endpoint: String::new(),
            model: String::new(),
            key: String::new(),
        };
        let mut answered = Answered::default();
        let output = wire.perform("runSql", "{}", &mut |_| Ok(String::new()), &mut answered);
        assert!(
            output.contains("There is no tool called 'runSql'"),
            "{output}"
        );
    }

    /// A number where a string was expected is still an argument. Models write `limit: 5` about as often as
    /// `limit: "5"`, and dropping it silently halves the answer.
    #[test]
    fn an_argument_written_as_a_number_is_still_an_argument() {
        let wire = Wire {
            kind: Kind::Local,
            endpoint: String::new(),
            model: String::new(),
            key: String::new(),
        };
        let mut answered = Answered::default();
        let mut seen = None;
        wire.perform(
            TOOL,
            r#"{"query":"topHosts","from":"24h","limit":5}"#,
            &mut |call| {
                seen = Some(call.clone());
                Ok("{}".to_owned())
            },
            &mut answered,
        );
        let call = seen.expect("the query should have run");
        assert_eq!(call.query, Query::TopHosts);
        assert_eq!(call.limit(), 5);
        assert_eq!(call.argument("from"), Some("24h"));
    }

    /// A model that prints its tool call instead of making it produces something that is not an answer.
    #[test]
    fn a_model_that_narrates_its_own_plumbing_is_tidied_up() {
        let messy =
            "```json\nsystem tools: {\"name\": \"runQuery\", \"arguments\": {}}\n```<|eot_id|>";
        assert!(cleaned(messy).contains("tool call instead of an answer"));
        assert_eq!(
            cleaned("Four requests, all to example.com."),
            "Four requests, all to example.com."
        );
        // A line that merely mentions a name is not a tool call.
        assert_eq!(
            cleaned("The busiest was \"name\" resolution at 12:00."),
            "The busiest was \"name\" resolution at 12:00."
        );
    }

    #[test]
    fn an_http_failure_says_what_to_do_about_it() {
        assert!(explain(401, "", "https://x.example").contains("rejected the key"));
        assert!(explain(404, "", "https://x.example").contains("not installed"));
        assert!(explain(500, "boom", "https://x.example").contains("boom"));
    }
}
