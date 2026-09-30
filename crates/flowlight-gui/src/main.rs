//! Flowlight's native interface.
//!
//! A window that runs as you, talking to a daemon that runs as root. The daemon holds the privileges, the
//! probes and the database; this holds a list and four buttons.
//!
//! That split is the reason this exists rather than the web page it replaces. A page on loopback is
//! reachable by every local user of the machine and guarded only by a token — a secret that leaks into
//! shell history, process listings and screenshots. A Unix socket has an owner and a mode, the kernel
//! enforces them, and there is no secret to leak. The page is still there for a machine with no desktop
//! session, where it is the only one of the two that works; it is served only when asked for.

mod protocol;

use adw::prelude::*;
use gtk::glib;
use protocol::{Agent, Coverage, Daemon, Request, Rule};
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

/// How often the window asks the daemon what has happened.
const REFRESH_SECONDS: u32 = 2;

/// How many recent requests to show.
const RECENT: usize = 300;

/// How many pages the switcher has.
const PAGES: usize = 7;

/// The windows the picker offers, and what each means in seconds.
const WINDOWS: &[(&str, i64)] = &[
    ("Last 15 minutes", 900),
    ("Last hour", 3_600),
    ("Last 6 hours", 21_600),
    ("Last 24 hours", 86_400),
    ("Last 7 days", 604_800),
];

fn main() -> glib::ExitCode {
    let socket = socket_from_arguments();
    let application = adw::Application::builder()
        .application_id("com.xinbetween.Flowlight")
        .build();
    application.connect_activate(move |application| build(application, socket.clone()));
    // The arguments were read above; handing them to GTK as well would have it reject `--socket`.
    application.run_with_args::<&str>(&[])
}

/// Where the daemon is, from `--socket` or the usual place.
fn socket_from_arguments() -> PathBuf {
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--socket"
            && let Some(path) = arguments.next()
        {
            return PathBuf::from(path);
        }
    }
    PathBuf::from(protocol::DEFAULT_SOCKET)
}

/// The six columns the switcher holds, one per page.
///
/// A struct rather than six arguments: the refresh function took eight and was about to take ten, and a
/// parameter list that long is one where two of them get swapped.
struct Pages {
    live: gtk::Box,
    ask: gtk::Box,
    agents: gtk::Box,
    rules: gtk::Box,
    coverage: gtk::Box,
    budget: gtk::Box,
    export: gtk::Box,
    intercept: gtk::Box,
}

/// What the window is currently looking at.
struct State {
    socket: PathBuf,
    /// How far back, in seconds.
    window: i64,
    /// What each page last drew, so that a second identical answer does not throw away the scroll
    /// position somebody was reading from.
    drawn: RefCell<[String; PAGES]>,
    /// The questions asked in this window and what came back.
    ///
    /// Held here rather than fetched, because a transcript is not something the daemon keeps: a question is
    /// answered and the answer belongs to whoever asked it.
    turns: RefCell<Vec<Turn>>,
    /// Whether a question is in flight, so the page can say so rather than looking broken for a minute.
    thinking: std::cell::Cell<bool>,
}

fn build(application: &adw::Application, socket: PathBuf) {
    let state = Rc::new(State {
        socket,
        window: WINDOWS.get(1).map_or(3_600, |(_, seconds)| *seconds),
        drawn: RefCell::new(Default::default()),
        turns: RefCell::new(Vec::new()),
        thinking: std::cell::Cell::new(false),
    });
    let window_seconds = Rc::new(RefCell::new(state.window));

    let stack = adw::ViewStack::new();
    let pages = Pages {
        live: page(&stack, "live", "Live", "network-transmit-receive-symbolic"),
        agents: page(&stack, "agents", "Agents", "system-users-symbolic"),
        rules: page(&stack, "rules", "Rules", "security-high-symbolic"),
        coverage: page(&stack, "coverage", "Coverage", "dialog-question-symbolic"),
        budget: page(&stack, "budget", "Budget", "emblem-important-symbolic"),
        export: page(&stack, "export", "Export", "send-to-symbolic"),
        ask: page(&stack, "ask", "Ask", "dialog-information-symbolic"),
        intercept: page(&stack, "intercept", "Intercept", "media-record-symbolic"),
    };

    let picker =
        gtk::DropDown::from_strings(&WINDOWS.iter().map(|(label, _)| *label).collect::<Vec<_>>());
    picker.set_selected(1);

    let status = gtk::Label::new(None);
    status.add_css_class("dim-label");

    let header = adw::HeaderBar::new();
    header.set_title_widget(Some(
        &adw::ViewSwitcher::builder()
            .stack(&stack)
            .policy(adw::ViewSwitcherPolicy::Wide)
            .build(),
    ));
    header.pack_start(&picker);
    header.pack_end(&status);

    // Shown only when the daemon says it is not enforcing. A window full of rules that do nothing is the
    // one thing worse than a window with no rules in it.
    let banner = adw::Banner::builder().revealed(false).build();
    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    content.append(&banner);
    content.append(&stack);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&content));

    let window = adw::ApplicationWindow::builder()
        .application(application)
        .title("Flowlight")
        .default_width(1_000)
        .default_height(720)
        .content(&toolbar)
        .build();
    window.present();

    {
        let window_seconds = Rc::clone(&window_seconds);
        let state = Rc::clone(&state);
        picker.connect_selected_notify(move |picker| {
            if let Some((_, seconds)) = WINDOWS.get(picker.selected() as usize) {
                *window_seconds.borrow_mut() = *seconds;
                // A different window is different data, so nothing that was drawn still stands.
                *state.drawn.borrow_mut() = Default::default();
            }
        });
    }

    {
        let socket = state.socket.clone();
        glib::spawn_future_local(async move {
            match fetch::<protocol::Hello>(socket, r#"{"op":"hello"}"#.to_owned()).await {
                Ok(hello) if !hello.enforcing => banner.set_title(
                    "This daemon is not enforcing rules. Rules can be written, and nothing will be \
                     refused.",
                ),
                Ok(hello) if !hello.storing => {
                    banner
                        .set_title("This daemon is storing nothing, so there is nothing to show.");
                }
                Ok(_) => return,
                Err(err) => banner.set_title(&err),
            }
            banner.set_revealed(true);
        });
    }

    glib::spawn_future_local(async move {
        loop {
            let seconds = *window_seconds.borrow();
            refresh(&state, seconds, &stack, &status, &pages).await;
            glib::timeout_future_seconds(REFRESH_SECONDS).await;
        }
    });
}

/// One page of the switcher: a scrolling, width-limited column to append groups to.
fn page(stack: &adw::ViewStack, name: &str, title: &str, icon: &str) -> gtk::Box {
    let column = gtk::Box::new(gtk::Orientation::Vertical, 18);
    column.set_margin_top(18);
    column.set_margin_bottom(36);
    column.set_margin_start(12);
    column.set_margin_end(12);

    let clamp = adw::Clamp::builder()
        .maximum_size(900)
        .child(&column)
        .build();
    let scroller = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&clamp)
        .build();
    stack.add_titled_with_icon(&scroller, Some(name), title, icon);
    column
}

/// Asks the daemon for whatever the visible page needs, and draws it.
///
/// Only the visible page. There is no reason to ask four questions a second when three of the answers are
/// behind another tab, and a machine being watched has better things to do.
async fn refresh(
    state: &Rc<State>,
    seconds: i64,
    stack: &adw::ViewStack,
    status: &gtk::Label,
    pages: &Pages,
) {
    let visible = stack.visible_child_name().unwrap_or_else(|| "live".into());
    let socket = state.socket.clone();

    match visible.as_str() {
        "agents" => {
            match fetch::<Vec<Agent>>(socket, protocol::windowed("agents", seconds)).await {
                Ok(rows) => {
                    draw(state, 1, &rows, &pages.agents, |column| {
                        render_agents(state, seconds, column, &rows);
                    });
                    say(status, "");
                }
                Err(err) => say(status, &err),
            }
        }
        "rules" => match fetch::<Vec<Rule>>(socket, r#"{"op":"rules"}"#.to_owned()).await {
            Ok(rows) => {
                draw(state, 2, &rows, &pages.rules, |column| {
                    render_rules(state, column, &rows);
                });
                say(status, "");
            }
            Err(err) => say(status, &err),
        },
        "budget" => {
            match fetch::<protocol::Budget>(socket, r#"{"op":"budget"}"#.to_owned()).await {
                Ok(row) => {
                    draw(state, 4, &row, &pages.budget, |column| {
                        render_budget(state, column, &row);
                    });
                    say(status, "");
                }
                Err(err) => say(status, &err),
            }
        }
        "ask" => match fetch::<protocol::Ask>(socket, r#"{"op":"model"}"#.to_owned()).await {
            Ok(row) => {
                // The transcript and the "thinking" flag are part of what is drawn, so a redraw happens when
                // an answer arrives and not only when the configuration changes.
                let conversation = Conversation {
                    model: &row,
                    turns: &state.turns.borrow(),
                    thinking: state.thinking.get(),
                };
                draw(state, 6, &conversation, &pages.ask, |column| {
                    render_ask(state, column, &row);
                });
                say(status, "");
            }
            Err(err) => say(status, &err),
        },
        "intercept" => {
            // Two questions for one page, because the configuration and the answers it uses are read
            // together and half of them is not worth drawing.
            let mocks =
                fetch::<Vec<protocol::Mock>>(socket.clone(), r#"{"op":"mocks"}"#.to_owned());
            match fetch::<protocol::Intercept>(socket, r#"{"op":"intercept"}"#.to_owned()).await {
                Ok(intercept) => {
                    let row = protocol::Interception {
                        intercept,
                        mocks: mocks.await.unwrap_or_default(),
                    };
                    draw(state, 7, &row, &pages.intercept, |column| {
                        render_intercept(state, column, &row);
                    });
                    say(status, "");
                }
                Err(err) => say(status, &err),
            }
        }
        "export" => {
            match fetch::<protocol::Export>(socket, r#"{"op":"export"}"#.to_owned()).await {
                Ok(row) => {
                    draw(state, 5, &row, &pages.export, |column| {
                        render_export(state, column, &row);
                    });
                    say(status, "");
                }
                Err(err) => say(status, &err),
            }
        }
        "coverage" => {
            match fetch::<Coverage>(socket, protocol::windowed("coverage", seconds)).await {
                Ok(row) => {
                    draw(state, 3, &row, &pages.coverage, |column| {
                        render_coverage(column, &row)
                    });
                    say(status, "");
                }
                Err(err) => say(status, &err),
            }
        }
        _ => match fetch::<Vec<Request>>(socket, protocol::recent(seconds, RECENT)).await {
            Ok(rows) => {
                draw(state, 0, &rows, &pages.live, |column| {
                    render_live(column, &rows)
                });
                say(status, "");
            }
            Err(err) => say(status, &err),
        },
    }
}

/// Redraws a page, but only when the answer has changed.
///
/// Rebuilding a list every two seconds throws away the scroll position somebody was reading from, which
/// makes a live view actively worse than a still one.
fn draw<T: serde::Serialize>(
    state: &Rc<State>,
    page: usize,
    data: &T,
    column: &gtk::Box,
    render: impl FnOnce(&gtk::Box),
) {
    let fingerprint = serde_json::to_string(data).unwrap_or_default();
    let mut drawn = state.drawn.borrow_mut();
    let Some(previous) = drawn.get_mut(page) else {
        return;
    };
    if *previous == fingerprint {
        return;
    }
    previous.clone_from(&fingerprint);
    drop(drawn);
    clear(column);
    render(column);
}

/// Says something in the corner, or nothing.
fn say(status: &gtk::Label, message: &str) {
    status.set_label(message);
    status.set_visible(!message.is_empty());
}

/// Empties a column.
fn clear(column: &gtk::Box) {
    while let Some(child) = column.first_child() {
        column.remove(&child);
    }
}

/// Asks the daemon one question, off the main thread.
///
/// A new connection each time rather than one held open: the daemon spawns a thread per connection and a
/// question every two seconds is not a load. What it buys is that a daemon which was restarted is simply
/// reachable again, with nothing here to reset.
async fn fetch<T: serde::de::DeserializeOwned + Send + 'static>(
    socket: PathBuf,
    request: String,
) -> Result<T, String> {
    let (sender, receiver) = async_channel::bounded(1);
    std::thread::spawn(move || {
        let answer = Daemon::connect(&socket)
            .and_then(|mut daemon| daemon.ask::<T>(&request))
            .map_err(|err| format!("{err:#}"));
        let _ = sender.send_blocking(answer);
    });
    receiver
        .recv()
        .await
        .unwrap_or_else(|_| Err("the question was never answered".to_owned()))
}

/// How long ago, in words.
fn ago(at: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() as i64);
    let seconds = (now - at).max(0);
    if seconds < 60 {
        format!("{seconds}s ago")
    } else if seconds < 3_600 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h ago", seconds / 3_600)
    } else {
        format!("{}d ago", seconds / 86_400)
    }
}

/// A size, in words.
fn size(bytes: i64) -> String {
    if bytes < 1_024 {
        format!("{bytes} B")
    } else if bytes < 1_048_576 {
        format!("{:.1} kB", bytes as f64 / 1_024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    }
}

/// The agent and the process, when they are not the same thing.
fn who(agent: Option<&str>, process: &str) -> String {
    match agent {
        Some(agent) if agent != process => format!("{agent}/{process}"),
        _ => process.to_owned(),
    }
}

fn render_live(column: &gtk::Box, rows: &[Request]) {
    if rows.is_empty() {
        column.append(&nothing(
            "Nothing read in this window",
            "That is not the same as nothing happening. Coverage says what could not be read.",
        ));
        return;
    }
    let group = adw::PreferencesGroup::new();
    for row in rows {
        let what = if let Some(rpc) = &row.rpc_method {
            match &row.rpc_tool {
                Some(tool) => format!("{rpc}  {tool}"),
                None => rpc.clone(),
            }
        } else if let Some(method) = &row.method {
            format!(
                "{method} {}{}",
                row.host.as_deref().unwrap_or(""),
                row.target.as_deref().unwrap_or("")
            )
        } else if let Some(status) = row.status {
            format!("{status}  ·  {}", size(i64::from(row.bytes)))
        } else if let Some(reason) = &row.unreadable {
            format!("HTTP/2 — {reason}")
        } else {
            size(i64::from(row.bytes))
        };
        let mut about = format!(
            "{}  ·  pid {}  ·  {}",
            who(row.agent.as_deref(), &row.process),
            row.pid,
            ago(row.at)
        );
        if row.confidence != "path" {
            about.push_str(&format!("  ·  named from {}", row.confidence));
        }
        if row.truncated {
            about.push_str("  ·  truncated");
        }
        let entry = adw::ActionRow::builder()
            .title(&what)
            .subtitle(&about)
            .build();
        entry.add_prefix(&gtk::Image::from_icon_name(if row.direction == "out" {
            "go-up-symbolic"
        } else {
            "go-down-symbolic"
        }));
        group.add(&entry);
    }
    column.append(&group);
}

fn render_agents(state: &Rc<State>, seconds: i64, column: &gtk::Box, rows: &[Agent]) {
    if rows.is_empty() {
        column.append(&nothing(
            "No agent has been seen in this window",
            "Flowlight recognises an agent by the name of its executable and attributes anything it \
             starts to it. A tool it does not recognise appears under its own name.",
        ));
        return;
    }
    for agent in rows {
        let group = adw::PreferencesGroup::builder()
            .title(&agent.agent)
            .description(format!(
                "{} requests from {} processes, {} hosts, {}, last {}",
                agent.requests,
                agent.processes,
                agent.hosts,
                size(agent.bytes),
                ago(agent.last_seen)
            ))
            .build();
        if !agent.local.is_empty() {
            group.add(
                &adw::ActionRow::builder()
                    .title(format!("{} local MCP server(s)", agent.local.len()))
                    .subtitle(format!(
                        "{} — these talk over a pipe, so nothing here can ever see them",
                        agent.local.join(", ")
                    ))
                    .build(),
            );
        }
        for domain in &agent.domains {
            let entry = adw::ActionRow::builder()
                .title(&domain.host)
                .subtitle(if domain.servers.is_empty() {
                    format!("{} requests", domain.requests)
                } else {
                    format!(
                        "{} requests  ·  configured as {}",
                        domain.requests,
                        domain.servers.join(", ")
                    )
                })
                .build();

            let standing = gtk::Label::new(Some(&domain.standing));
            standing.add_css_class("caption");
            standing.add_css_class(match domain.standing.as_str() {
                "unexpected" => "error",
                "unused" => "warning",
                "used" => "success",
                _ => "dim-label",
            });
            entry.add_suffix(&standing);

            // The two buttons the macOS build settled on: this agent only, or everywhere.
            entry.add_suffix(&block_button(
                state,
                seconds,
                "Block for this agent",
                &domain.host,
                Some(&agent.agent),
            ));
            entry.add_suffix(&block_button(
                state,
                seconds,
                "Block everywhere",
                &domain.host,
                None,
            ));
            group.add(&entry);
        }
        if !agent.tools.is_empty() {
            let said = adw::PreferencesGroup::builder()
                .title("What it said")
                .description(
                    "Read out of MCP's own protocol, which is JSON-RPC in the plaintext already being \
                     captured. The tool's name, never its arguments.",
                )
                .build();
            for tool in &agent.tools {
                said.add(
                    &adw::ActionRow::builder()
                        .title(match &tool.tool {
                            Some(name) => format!("{}  {name}", tool.method),
                            None => tool.method.clone(),
                        })
                        .subtitle(format!(
                            "{}  ·  {} call{}  ·  last {}",
                            tool.host,
                            tool.calls,
                            if tool.calls == 1 { "" } else { "s" },
                            ago(tool.last_seen)
                        ))
                        .build(),
                );
            }
            column.append(&said);
        }
        column.append(&group);
    }
}

/// A button that asks what a rule would do, and writes it only if somebody says so.
///
/// Asking first is the point. The macOS build learned it the long way: a rule nobody can preview is a rule
/// nobody enables, and the commonest answer — "this would change nothing" — is the most useful one.
fn block_button(
    state: &Rc<State>,
    seconds: i64,
    tooltip: &str,
    host: &str,
    agent: Option<&str>,
) -> gtk::Button {
    let button = gtk::Button::builder()
        .icon_name(if agent.is_some() {
            "avatar-default-symbolic"
        } else {
            "action-unavailable-symbolic"
        })
        .tooltip_text(tooltip)
        .valign(gtk::Align::Center)
        .build();
    button.add_css_class("flat");

    let state = Rc::clone(state);
    let host = host.to_owned();
    let agent = agent.map(str::to_owned);
    let heading = tooltip.to_owned();
    button.connect_clicked(move |button| {
        let state = Rc::clone(&state);
        let host = host.clone();
        let agent = agent.clone();
        let heading = heading.clone();
        let root = button.root().and_downcast::<gtk::Window>();
        glib::spawn_future_local(async move {
            let changes: Result<Vec<protocol::Change>, String> = fetch(
                state.socket.clone(),
                protocol::simulate("block", &host, 0, agent.as_deref(), seconds),
            )
            .await;
            let body = match &changes {
                Ok(changes) if changes.is_empty() => format!(
                    "Nothing in this window would have been decided differently. Either a rule you \
                     already have covers {host}, or this machine has not reached it."
                ),
                Ok(changes) => {
                    let total: i64 = changes.iter().map(|change| change.occurrences).sum();
                    let mut lines = format!(
                        "{total} request(s) or connection(s) in this window would have been refused:\n"
                    );
                    for change in changes.iter().take(8) {
                        lines.push_str(&format!("\n  {}  ×{}", change.subject, change.occurrences));
                    }
                    if changes.len() > 8 {
                        lines.push_str(&format!("\n  … and {} more", changes.len() - 8));
                    }
                    lines.push_str(
                        "\n\nThis is a claim about the past, not a promise about the future.",
                    );
                    lines
                }
                Err(err) => format!("What this would change could not be worked out: {err}"),
            };

            let dialog = adw::AlertDialog::builder()
                .heading(&heading)
                .body(&body)
                .build();
            dialog.add_response("cancel", "Cancel");
            dialog.add_response("block", "Block");
            dialog.set_response_appearance("block", adw::ResponseAppearance::Destructive);
            dialog.set_default_response(Some("cancel"));
            dialog.set_close_response("cancel");

            let answer = dialog.choose_future(root.as_ref()).await;
            if answer != "block" {
                return;
            }
            let _: Result<String, String> = fetch(
                state.socket.clone(),
                protocol::write_rule("block", &host, 0, agent.as_deref()),
            )
            .await;
            // Whatever happened, what is on screen no longer reflects the rules.
            *state.drawn.borrow_mut() = Default::default();
        });
    });
    button
}

fn render_rules(state: &Rc<State>, column: &gtk::Box, rows: &[Rule]) {
    let group = adw::PreferencesGroup::builder()
        .title("Rules")
        .description(
            "The most specific rule wins: subject, then port, then scope. Nothing is refused unless a \
             rule says so.",
        )
        .build();

    if rows.is_empty() {
        group.add(
            &adw::ActionRow::builder()
                .title("No rules")
                .subtitle("Nothing is being refused.")
                .build(),
        );
    }
    for rule in rows {
        let scope = rule
            .scope
            .strip_prefix("agent:")
            .map_or_else(|| "everyone".to_owned(), |agent| format!("{agent} only"));
        let port = if rule.port == 0 {
            "any port".to_owned()
        } else {
            format!("port {}", rule.port)
        };
        let mut about = format!("{scope}  ·  {port}");
        if let Some(note) = &rule.note {
            about.push_str(&format!("  ·  {note}"));
        }
        let entry = adw::ActionRow::builder()
            .title(format!("{} {}", rule.action, rule.subject))
            .subtitle(&about)
            .build();

        let forget = gtk::Button::builder()
            .icon_name("user-trash-symbolic")
            .tooltip_text("Forget this rule")
            .valign(gtk::Align::Center)
            .build();
        forget.add_css_class("flat");
        let socket = state.socket.clone();
        let request = protocol::forget(rule.id);
        let state = Rc::clone(state);
        forget.connect_clicked(move |forget| {
            forget.set_sensitive(false);
            let socket = socket.clone();
            let request = request.clone();
            let state = Rc::clone(&state);
            glib::spawn_future_local(async move {
                let _: Result<bool, String> = fetch(socket, request).await;
                *state.drawn.borrow_mut() = Default::default();
            });
        });
        entry.add_suffix(&forget);
        group.add(&entry);
    }
    column.append(&group);
}

fn render_coverage(column: &gtk::Box, row: &Coverage) {
    let read = adw::PreferencesGroup::builder()
        .title("What was read")
        .build();
    read.add(&counted(
        "Requests",
        row.requests,
        &format!(
            "from {} processes, over {} connections",
            row.processes_read, row.connections
        ),
    ));
    column.append(&read);

    let unread = adw::PreferencesGroup::builder()
        .title("What was not")
        .description(
            "A process that opened HTTPS connections and had nothing read from them is using a TLS \
             implementation there is no probe for. Go links its own into the binary, and so does Chrome.",
        )
        .build();
    if row.unread.is_empty() {
        unread.add(
            &adw::ActionRow::builder()
                .title("Nothing")
                .subtitle("Every process that opened an HTTPS connection was read.")
                .build(),
        );
    }
    for process in &row.unread {
        unread.add(&counted(
            &process.process,
            process.connections,
            "connections, nothing read",
        ));
    }
    column.append(&unread);

    let imperfect = adw::PreferencesGroup::builder()
        .title("Read imperfectly")
        .description(
            "Zeroes are shown. A line that disappears when it reads zero turns \"nothing was \
                      dropped\" into \"nobody checked\".",
        )
        .build();
    for (title, value, about) in [
        (
            "Truncated",
            row.truncated,
            "carried more than four kilobytes; the rest was not captured",
        ),
        (
            "Undecodable",
            row.undecodable,
            "HTTP/2 connections that could not be followed",
        ),
        (
            "Named weakly",
            row.named_by_comm,
            "named from the kernel's copy, cut at fifteen characters",
        ),
        (
            "Unnamed",
            row.named_by_pid,
            "no name was available; the identity is a process id",
        ),
        (
            "Refused",
            row.refused,
            "refused before the handshake, because a rule said so",
        ),
        (
            "Dropped",
            row.dropped,
            "records the kernel had nowhere to put",
        ),
    ] {
        imperfect.add(&counted(title, value, about));
    }
    column.append(&imperfect);

    if !row.unprobed.is_empty() {
        let unprobed = adw::PreferencesGroup::builder()
            .title("Libraries that could not be probed")
            .build();
        for library in &row.unprobed {
            unprobed.add(
                &adw::ActionRow::builder()
                    .title(&library.path)
                    .subtitle(&library.reason)
                    .build(),
            );
        }
        column.append(&unprobed);
    }
}

/// A row that is mostly a number.
fn counted(title: &str, value: i64, about: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(title)
        .subtitle(about)
        .build();
    let label = gtk::Label::new(Some(&value.to_string()));
    label.add_css_class("title-2");
    label.add_css_class("numeric");
    row.add_suffix(&label);
    row
}

/// A page with nothing on it, and a sentence about why.
fn nothing(title: &str, about: &str) -> adw::StatusPage {
    adw::StatusPage::builder()
        .icon_name("network-offline-symbolic")
        .title(title)
        .description(about)
        .vexpand(true)
        .build()
}

/// The budget: what Flowlight is allowed to read, and for how long.
///
/// The sentences first, the controls after. Somebody arriving here wants to know what is happening before
/// they want a switch, and seven numbers do not tell them.
fn render_budget(state: &Rc<State>, column: &gtk::Box, row: &protocol::Budget) {
    let said = adw::PreferencesGroup::builder()
        .title("What is being read")
        .build();
    for sentence in &row.described {
        said.add(&adw::ActionRow::builder().title(sentence).build());
    }
    column.append(&said);

    let controls = adw::PreferencesGroup::builder()
        .title("Limits")
        .description(
            "Changing one of these changes only that one. A running daemon picks it up within a couple of \
             seconds.",
        )
        .build();

    let payloads = adw::SwitchRow::builder()
        .title("Read payloads")
        .subtitle(
            "Connections are attributed either way. This decides whether what they carry is read.",
        )
        .active(row.payloads)
        .build();
    controls.add(&payloads);
    {
        let state = Rc::clone(state);
        payloads.connect_active_notify(move |switch| {
            change(&state, "payloads", &switch.is_active().to_string());
        });
    }

    let renew = adw::ActionRow::builder()
        .title("Session")
        .subtitle(match row.session_remaining {
            Some(0) => "Run out. Nothing is being read.".to_owned(),
            Some(remaining) => format!("{} left.", duration(remaining)),
            None => "No limit, which was asked for rather than assumed.".to_owned(),
        })
        .build();
    let renew_button = gtk::Button::builder()
        .label("Renew")
        .valign(gtk::Align::Center)
        .build();
    {
        let state = Rc::clone(state);
        renew_button.connect_clicked(move |_| change(&state, "renew", "true"));
    }
    renew.add_suffix(&renew_button);
    controls.add(&renew);

    // Eight hours is the default and the reason it exists; the rest are the answers people actually want.
    let choices = ["30 minutes", "2 hours", "8 hours", "24 hours", "No limit"];
    let minutes = [30_u32, 120, 480, 1_440, 0];
    let session = adw::ComboRow::builder()
        .title("Stop reading after")
        .subtitle(
            "You turned this on to look at something. It should not still be running next week.",
        )
        .model(&gtk::StringList::new(&choices))
        .build();
    session.set_selected(
        minutes
            .iter()
            .position(|candidate| *candidate == row.session_minutes)
            .unwrap_or(2) as u32,
    );
    controls.add(&session);
    {
        let state = Rc::clone(state);
        session.connect_selected_notify(move |combo| {
            if let Some(chosen) = minutes.get(combo.selected() as usize) {
                change(&state, "session_minutes", &chosen.to_string());
            }
        });
    }

    let paths_choices = ["The whole path", "The host only", "Neither"];
    let paths_values = ["full", "host-only", "none"];
    let paths = adw::ComboRow::builder()
        .title("Keep of each request")
        .subtitle("Credentials are already removed. A path can still say more than somebody would choose.")
        .model(&gtk::StringList::new(&paths_choices))
        .build();
    paths.set_selected(
        paths_values
            .iter()
            .position(|candidate| *candidate == row.paths)
            .unwrap_or(0) as u32,
    );
    controls.add(&paths);
    {
        let state = Rc::clone(state);
        paths.connect_selected_notify(move |combo| {
            if let Some(chosen) = paths_values.get(combo.selected() as usize) {
                change(&state, "paths", &format!("\"{chosen}\""));
            }
        });
    }

    column.append(&controls);

    let keeping = adw::PreferencesGroup::builder()
        .title("How long it is kept")
        .description(
            "Detail answers what happened. The summary answers whether it was normal, and is what expired \
             detail is folded into rather than what replaces it.",
        )
        .build();
    keeping.add(
        &adw::ActionRow::builder()
            .title("Individual requests")
            .subtitle(format!("{} days", row.detail_days))
            .build(),
    );
    keeping.add(
        &adw::ActionRow::builder()
            .title("Daily summary")
            .subtitle(format!("{} days", row.summary_days))
            .build(),
    );
    column.append(&keeping);
}

/// Export: where what was seen is sent, and what agreeing to that means.
///
/// The disclosure is first and the agreement is a dialog with the same sentences in it. That is deliberate
/// duplication: a switch labelled "send my data somewhere" that somebody flicks without reading the page is
/// exactly the consent this is built to avoid.
fn render_export(state: &Rc<State>, column: &gtk::Box, row: &protocol::Export) {
    let said = adw::PreferencesGroup::builder()
        .title(if row.sending {
            "What is being sent"
        } else {
            "What would be sent"
        })
        .build();
    for sentence in &row.disclosure {
        said.add(&adw::ActionRow::builder().title(sentence).build());
    }
    if let Some(reason) = &row.why_not {
        said.add(
            &adw::ActionRow::builder()
                .title("Nothing is being sent")
                .subtitle(reason)
                .build(),
        );
    }
    column.append(&said);

    let where_to = adw::PreferencesGroup::builder()
        .title("Where")
        .description(
            "An absolute path is a file on this machine and nothing crosses the network. An http(s) URL is              an OTLP collector and something does.",
        )
        .build();
    let destination = adw::EntryRow::builder()
        .title("Destination")
        .text(row.destination.clone().unwrap_or_default())
        .show_apply_button(true)
        .build();
    {
        let state = Rc::clone(state);
        destination.connect_apply(move |entry| {
            let text = entry.text().to_string();
            let value = serde_json::to_string(&text).unwrap_or_else(|_| "\"\"".to_owned());
            change_export(&state, "destination", &value);
        });
    }
    where_to.add(&destination);
    if row.headers.is_empty() {
        where_to.add(
            &adw::ActionRow::builder()
                .title("No headers")
                .subtitle(
                    "A collector that needs a token wants one: `flowlightd export --header                      Authorization=…`. Set here or there, the value is never shown back.",
                )
                .build(),
        );
    } else {
        where_to.add(
            &adw::ActionRow::builder()
                .title("Headers")
                // Names only. This window ends up in screenshots like any other.
                .subtitle(row.headers.join(", "))
                .build(),
        );
    }
    column.append(&where_to);

    let chosen = adw::PreferencesGroup::builder()
        .title("What")
        .description(
            "Changing any of these takes away an agreement that was to something else. Nothing is sent              again until the new sentences are agreed to.",
        )
        .build();
    for field in &row.every_field {
        let switch = adw::SwitchRow::builder()
            .title(field.replace('_', " "))
            .active(row.fields.contains(field))
            .build();
        let state = Rc::clone(state);
        let wanted = row.fields.clone();
        let field = field.clone();
        switch.connect_active_notify(move |switch| {
            let mut fields: Vec<String> = wanted.clone();
            if switch.is_active() {
                if !fields.contains(&field) {
                    fields.push(field.clone());
                }
            } else {
                fields.retain(|candidate| candidate != &field);
            }
            if fields.is_empty() {
                // A list with nothing in it would send empty records, which the daemon refuses. Refusing it
                // here as well keeps the switch from lying about what it did.
                switch.set_active(true);
                return;
            }
            let value = serde_json::to_string(&fields).unwrap_or_else(|_| "[]".to_owned());
            change_export(&state, "fields", &value);
        });
        chosen.add(&switch);
    }
    column.append(&chosen);

    let agreement = adw::PreferencesGroup::builder().title("Agreement").build();
    let state_of_it = adw::ActionRow::builder()
        .title(if row.consented {
            "Agreed to the sentences above"
        } else {
            "Not agreed"
        })
        .subtitle(if row.sent_through > 0 {
            "Records already sent are not sent again.".to_owned()
        } else {
            "Everything stored and not yet sent goes in the first batch.".to_owned()
        })
        .build();
    let button = gtk::Button::builder()
        .label(if row.consented {
            "Take it back"
        } else {
            "Agree"
        })
        .valign(gtk::Align::Center)
        .build();
    if row.consented {
        button.add_css_class("destructive-action");
    } else {
        button.add_css_class("suggested-action");
    }
    {
        let state = Rc::clone(state);
        let consented = row.consented;
        let sentences = row.disclosure.join("\n\n");
        let destination = row.destination.clone();
        button.connect_clicked(move |button| {
            if consented {
                change_export(&state, "off", "true");
                return;
            }
            let state = Rc::clone(&state);
            let sentences = sentences.clone();
            let destination = destination.clone();
            let root = button.root().and_downcast::<gtk::Window>();
            glib::spawn_future_local(async move {
                if destination.is_none() {
                    return;
                }
                let dialog = adw::AlertDialog::builder()
                    .heading("Agree to this?")
                    .body(sentences)
                    .build();
                dialog.add_response("cancel", "Cancel");
                dialog.add_response("agree", "Agree");
                dialog.set_response_appearance("agree", adw::ResponseAppearance::Suggested);
                dialog.set_default_response(Some("cancel"));
                dialog.set_close_response("cancel");
                if dialog.choose_future(root.as_ref()).await != "agree" {
                    return;
                }
                change_export(&state, "consent", "true");
            });
        });
    }
    state_of_it.add_suffix(&button);
    agreement.add(&state_of_it);
    column.append(&agreement);
}

/// One question asked in this window, and what came back.
#[derive(Debug, Clone, serde::Serialize)]
struct Turn {
    question: String,
    answer: String,
    /// The queries the model ran, as a line each.
    work: Vec<String>,
    /// What went wrong, if the question could not be answered.
    failure: Option<String>,
}

/// What the Ask page draws: the configuration and the conversation together.
#[derive(serde::Serialize)]
struct Conversation<'a> {
    model: &'a protocol::Ask,
    turns: &'a [Turn],
    thinking: bool,
}

/// Ask: a question about this machine, answered by a model somebody configured.
///
/// The disclosure is above the box you type in, not behind a settings button. There is no model in Flowlight
/// for Linux, so every question goes somewhere — and where that is should be on the screen where the question
/// is asked.
fn render_ask(state: &Rc<State>, column: &gtk::Box, row: &protocol::Ask) {
    let said = adw::PreferencesGroup::builder()
        .title("What asking means")
        .build();
    for sentence in &row.disclosure {
        said.add(&adw::ActionRow::builder().title(sentence).build());
    }
    if let Some(reason) = &row.why_not {
        said.add(
            &adw::ActionRow::builder()
                .title("Not ready")
                .subtitle(reason)
                .build(),
        );
    }
    column.append(&said);

    let asking = adw::PreferencesGroup::builder().title("Ask").build();
    let entry = adw::EntryRow::builder()
        .title("Your question")
        .show_apply_button(true)
        .sensitive(row.ready && !state.thinking.get())
        .build();
    {
        let state = Rc::clone(state);
        entry.connect_apply(move |entry| {
            let asked = entry.text().to_string();
            if asked.trim().is_empty() {
                return;
            }
            entry.set_text("");
            ask_the_model(&state, &asked);
        });
    }
    asking.add(&entry);
    if state.thinking.get() {
        asking.add(
            &adw::ActionRow::builder()
                .title("Thinking…")
                .subtitle(
                    "A model running on this machine can take a while over the first question.",
                )
                .build(),
        );
    }
    column.append(&asking);

    for turn in state.turns.borrow().iter().rev() {
        let group = adw::PreferencesGroup::builder()
            .title(turn.question.clone())
            .build();
        match &turn.failure {
            Some(failure) => group.add(
                &adw::ActionRow::builder()
                    .title("That could not be answered")
                    .subtitle(failure.clone())
                    .build(),
            ),
            None => group.add(
                &adw::ActionRow::builder()
                    .title(turn.answer.clone())
                    .subtitle(if turn.work.is_empty() {
                        // An answer with no queries under it is a sentence a model made up, and saying so is
                        // more useful than leaving the space blank.
                        "No queries were run for this, so it is not an answer about this machine."
                            .to_owned()
                    } else {
                        turn.work.join("  ·  ")
                    })
                    .build(),
            ),
        }
        column.append(&group);
    }

    let configuring = adw::PreferencesGroup::builder()
        .title("Which model")
        .description(
            "Flowlight for Linux has no model of its own. A server on this machine sends nothing anywhere; \
             a provider needs a key, which goes in a file that only root can read — `flowlightd model \
             --key-file PATH`.",
        )
        .build();

    let kinds: Vec<&str> = row.every_kind.iter().map(String::as_str).collect();
    let kind = adw::ComboRow::builder()
        .title("Provider")
        .model(&gtk::StringList::new(&kinds))
        .build();
    kind.set_selected(
        row.every_kind
            .iter()
            .position(|candidate| *candidate == row.kind)
            .unwrap_or(0) as u32,
    );
    {
        let state = Rc::clone(state);
        let every = row.every_kind.clone();
        kind.connect_selected_notify(move |combo| {
            if let Some(chosen) = every.get(combo.selected() as usize) {
                change_model(&state, "kind", &format!("\"{chosen}\""));
            }
        });
    }
    configuring.add(&kind);

    let endpoint = adw::EntryRow::builder()
        .title("Endpoint")
        .text(row.endpoint.clone().unwrap_or_default())
        .show_apply_button(true)
        .build();
    {
        let state = Rc::clone(state);
        endpoint.connect_apply(move |entry| {
            let value = serde_json::to_string(&entry.text().to_string())
                .unwrap_or_else(|_| "\"\"".to_owned());
            change_model(&state, "endpoint", &value);
        });
    }
    configuring.add(&endpoint);

    let model = adw::EntryRow::builder()
        .title("Model")
        .text(row.model.clone().unwrap_or_default())
        .show_apply_button(true)
        .build();
    {
        let state = Rc::clone(state);
        model.connect_apply(move |entry| {
            let value = serde_json::to_string(&entry.text().to_string())
                .unwrap_or_else(|_| "\"\"".to_owned());
            change_model(&state, "model", &value);
        });
    }
    configuring.add(&model);

    if row.needs_key {
        configuring.add(
            &adw::ActionRow::builder()
                .title(if row.key_on_file {
                    "A key is on file"
                } else {
                    "No key on file"
                })
                // Never an entry for it. A key typed into a window is a key in that window's memory and, the
                // moment anything goes wrong, in a screenshot.
                .subtitle("Set it with `sudo flowlightd model --key-file PATH`.")
                .build(),
        );
    }
    column.append(&configuring);
}

/// Asks the question, and lets the page redraw when there is an answer.
fn ask_the_model(state: &Rc<State>, asked: &str) {
    state.thinking.set(true);
    *state.drawn.borrow_mut() = Default::default();
    let socket = state.socket.clone();
    let request = protocol::question(asked);
    let asked = asked.to_owned();
    let state = Rc::clone(state);
    glib::spawn_future_local(async move {
        let answered: Result<protocol::Answered, String> = fetch(socket, request).await;
        let turn = match answered {
            Ok(answered) => Turn {
                question: asked,
                answer: answered.answer,
                work: answered
                    .calls
                    .iter()
                    .map(|ran| {
                        if ran.failed {
                            format!("{} (refused)", ran.query)
                        } else {
                            ran.query.clone()
                        }
                    })
                    .collect(),
                failure: None,
            },
            Err(err) => Turn {
                question: asked,
                answer: String::new(),
                work: Vec::new(),
                failure: Some(err),
            },
        };
        state.turns.borrow_mut().push(turn);
        state.thinking.set(false);
        *state.drawn.borrow_mut() = Default::default();
    });
}

/// Changes one field of the model configuration.
fn change_model(state: &Rc<State>, field: &str, value: &str) {
    let socket = state.socket.clone();
    let request = protocol::set_model(field, value);
    let state = Rc::clone(state);
    glib::spawn_future_local(async move {
        let _: Result<serde_json::Value, String> = fetch(socket, request).await;
        *state.drawn.borrow_mut() = Default::default();
    });
}

/// Intercept: the one page whose switch changes what an application sees.
///
/// The disclosure is above the switch, and the switch is the last thing on the page rather than the first. A
/// page that led with "terminate my agents' connections" and explained afterwards would be a page people flick
/// and then wonder about.
fn render_intercept(state: &Rc<State>, column: &gtk::Box, row: &protocol::Interception) {
    let said = adw::PreferencesGroup::builder()
        .title(if row.intercept.running {
            "What is happening"
        } else {
            "What turning this on would mean"
        })
        .build();
    for sentence in &row.intercept.disclosure {
        said.add(&adw::ActionRow::builder().title(sentence).build());
    }
    if let Some(reason) = &row.intercept.why_not {
        said.add(
            &adw::ActionRow::builder()
                .title("Nothing is being terminated")
                .subtitle(reason)
                .build(),
        );
    }
    column.append(&said);

    let answers = adw::PreferencesGroup::builder()
        .title("Canned answers")
        .description(
            "The first one that matches a request answers it; everything else goes to the server untouched. \
             A host with no answer is never terminated at all, so no certificate is presented for it.",
        )
        .build();
    if row.mocks.is_empty() {
        answers.add(
            &adw::ActionRow::builder()
                .title("None")
                .subtitle("`flowlightd mock <host> --status 503` writes one.")
                .build(),
        );
    }
    for mock in &row.mocks {
        let line = adw::ActionRow::builder()
            .title(format!(
                "{} {}{}",
                if mock.method.is_empty() {
                    "ANY"
                } else {
                    &mock.method
                },
                mock.subject,
                mock.path
            ))
            .subtitle(format!(
                "answers {}{}{}{}",
                mock.status,
                if mock.refusal { ", as a refusal" } else { "" },
                if mock.delay > 0 {
                    format!(", after {} second(s)", mock.delay)
                } else {
                    String::new()
                },
                if mock.enabled {
                    ""
                } else {
                    " — switched off"
                }
            ))
            .build();
        let forget = gtk::Button::builder()
            .icon_name("user-trash-symbolic")
            .tooltip_text("Forget this answer")
            .valign(gtk::Align::Center)
            .build();
        forget.add_css_class("flat");
        {
            let state = Rc::clone(state);
            let id = mock.id;
            forget.connect_clicked(move |_| {
                let socket = state.socket.clone();
                let request = protocol::forget_mock(id);
                let state = Rc::clone(&state);
                glib::spawn_future_local(async move {
                    let _: Result<serde_json::Value, String> = fetch(socket, request).await;
                    *state.drawn.borrow_mut() = Default::default();
                });
            });
        }
        line.add_suffix(&forget);
        answers.add(&line);
    }
    column.append(&answers);

    let scope = adw::PreferencesGroup::builder()
        .title("Scope")
        .description(
            "Interception applies to the agents named here and to nothing else on this machine. Empty means \
             nobody.",
        )
        .build();
    for (title, values, field) in [
        (
            "Agents, separated by commas",
            row.intercept.agents.clone(),
            "agents",
        ),
        (
            "Never terminate, separated by commas",
            row.intercept.never.clone(),
            "never",
        ),
    ] {
        let entry = adw::EntryRow::builder()
            .title(title)
            .text(values.join(", "))
            .show_apply_button(true)
            .build();
        let state = Rc::clone(state);
        entry.connect_apply(move |entry| {
            let named: Vec<String> = entry
                .text()
                .split(',')
                .map(|part| part.trim().to_owned())
                .filter(|part| !part.is_empty())
                .collect();
            let value = serde_json::to_string(&named).unwrap_or_else(|_| "[]".to_owned());
            change_intercept(&state, field, &value);
        });
        scope.add(&entry);
    }
    column.append(&scope);

    let certificate = adw::PreferencesGroup::builder()
        .title("The certificate")
        .description(
            "Anything in scope has to trust it, or it will refuse the connection — which is what a pinned \
             certificate is supposed to do. `sudo flowlightd trust` says what to tell each thing.",
        )
        .build();
    certificate.add(
        &adw::ActionRow::builder()
            .title("Certificate")
            .subtitle(
                row.intercept
                    .certificate
                    .clone()
                    .unwrap_or_else(|| "not made yet".to_owned()),
            )
            .build(),
    );
    if let Some(bundle) = &row.intercept.bundle {
        certificate.add(
            &adw::ActionRow::builder()
                .title("This machine's roots plus it")
                .subtitle(bundle.clone())
                .build(),
        );
    }
    column.append(&certificate);

    // Last, and with the disclosure above it.
    let switch = adw::PreferencesGroup::builder().title("Switch").build();
    let on = adw::SwitchRow::builder()
        .title("Terminate connections from the agents above")
        .subtitle(
            "Off by default. This is the only thing Flowlight does that changes what an application sees.",
        )
        .active(row.intercept.enabled)
        .build();
    {
        let state = Rc::clone(state);
        on.connect_active_notify(move |switch| {
            let field = if switch.is_active() { "on" } else { "off" };
            change_intercept(&state, field, "true");
        });
    }
    switch.add(&on);
    column.append(&switch);
}

/// Changes one field of the interception configuration.
fn change_intercept(state: &Rc<State>, field: &str, value: &str) {
    let socket = state.socket.clone();
    let request = protocol::set_intercept(field, value);
    let state = Rc::clone(state);
    glib::spawn_future_local(async move {
        let _: Result<serde_json::Value, String> = fetch(socket, request).await;
        *state.drawn.borrow_mut() = Default::default();
    });
}

/// Changes one field of the export configuration and lets the next refresh show the result.
fn change_export(state: &Rc<State>, field: &str, value: &str) {
    let socket = state.socket.clone();
    let request = protocol::set_export(field, value);
    let state = Rc::clone(state);
    glib::spawn_future_local(async move {
        let _: Result<serde_json::Value, String> = fetch(socket, request).await;
        *state.drawn.borrow_mut() = Default::default();
    });
}

/// Changes one field of the budget and lets the next refresh show the result.
fn change(state: &Rc<State>, field: &str, value: &str) {
    let socket = state.socket.clone();
    let request = protocol::set_budget(field, value);
    let state = Rc::clone(state);
    glib::spawn_future_local(async move {
        let _: Result<serde_json::Value, String> = fetch(socket, request).await;
        *state.drawn.borrow_mut() = Default::default();
    });
}

/// A length of time, in words.
fn duration(seconds: i64) -> String {
    if seconds < 60 {
        format!("{seconds} seconds")
    } else if seconds < 3_600 {
        format!("{} minutes", seconds / 60)
    } else {
        let hours = seconds / 3_600;
        let minutes = (seconds % 3_600) / 60;
        if minutes == 0 {
            format!("{hours} hours")
        } else {
            format!("{hours} hours and {minutes} minutes")
        }
    }
}
