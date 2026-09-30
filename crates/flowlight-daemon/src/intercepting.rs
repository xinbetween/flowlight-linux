//! Turning interception on: the kernel's redirect, the proxy's listeners, and the scope they obey.
//!
//! The kernel rewrites an agent's destination to a port on this machine and writes down where it was going.
//! The proxy accepts the connection, asks which destination belongs to this source port, and decides. This
//! file is the part in between: it attaches the programs, keeps the scope maps in step with what somebody
//! configured, and runs the listeners.
//!
//! # Why the blocking programs are attached first
//!
//! Both hang off the same hook, and the kernel runs them in the order they were attached. Blocking decides
//! about the address in the context; redirect *changes* that address. Attached the other way round, a rule
//! refusing `1.2.3.4` would be asked about `127.0.0.1` instead and would let the connection through — so
//! turning interception on would quietly disable blocking for everything in its scope.

use anyhow::{Context as _, Result, anyhow, bail};
use aya::Ebpf;
use aya::maps::{Array, HashMap as BpfHashMap, MapData};
use aya::programs::{CgroupAttachMode, CgroupSockAddr, SockOps};
use flowlight_common::redirect::{IN_SCOPE, Original, PROXY_PORT};
use flowlight_proxy::{Authority, Decided, Proxy, Reached};
use flowlight_store::{Intercept, Mock};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::Sender;

/// The port that is redirected. HTTPS, because the proxy speaks TLS and nothing else.
///
/// Plain HTTP is not redirected: there is nothing to terminate, the payload probes already read it in the
/// clear, and a proxy in front of it would be a change to the machine for no information at all.
const HTTPS: u16 = 443;

/// What happened to one connection, on its way to be recorded.
#[derive(Debug, Clone)]
pub struct Happened {
    /// The process that opened it, so the main loop can attribute it the way it attributes everything else.
    pub tgid: u32,
    /// What the proxy decided.
    pub decided: Decided,
}

impl Happened {
    /// Whether this is worth keeping rather than only counting.
    ///
    /// A connection that was passed through or forwarded untouched is the ordinary case, and a note per
    /// connection would bury the ones that matter. What is kept is what Flowlight *did*: a request it
    /// answered, and a connection it could not carry.
    pub fn is_worth_keeping(&self) -> bool {
        matches!(
            self.decided,
            Decided::Answered { .. } | Decided::Failed { .. }
        )
    }

    /// How this reads in a note and on a line.
    pub fn describe(&self) -> (String, String, String) {
        match &self.decided {
            Decided::Answered {
                host,
                rules,
                refusal,
            } => (
                if *refusal {
                    "refused-request".to_owned()
                } else {
                    "mocked".to_owned()
                },
                host.clone(),
                format!(
                    "{} by rule {}",
                    if *refusal {
                        "a request was refused"
                    } else {
                        "a request was answered by Flowlight rather than by the server"
                    },
                    rules
                        .iter()
                        .map(|id| id.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ),
            Decided::Failed { host, why } => (
                "intercept-failed".to_owned(),
                host.clone().unwrap_or_else(|| "an unknown host".to_owned()),
                why.clone(),
            ),
            Decided::Forwarded { host, requests } => (
                "forwarded".to_owned(),
                host.clone(),
                format!("{requests} request(s) went through untouched"),
            ),
            Decided::Passed { host } => (
                "passed".to_owned(),
                host.clone().unwrap_or_else(|| "an unnamed host".to_owned()),
                "not terminated: no rule could answer for it".to_owned(),
            ),
        }
    }
}

/// The maps the redirect is steered with.
pub struct Interception {
    agents: BpfHashMap<MapData, u32, u8>,
    ports: BpfHashMap<MapData, u16, u8>,
    to: Array<MapData, u16>,
    proxy: Arc<Proxy>,
    /// What is in force, so a pass that changes nothing writes nothing.
    running: Option<Intercept>,
    /// Which agent identifiers are in the kernel's scope map.
    scoped: std::collections::HashSet<u32>,
    /// The port the listeners are on, once they are up.
    port: Option<u16>,
}

impl Interception {
    /// Attaches the redirect programs and takes the maps.
    ///
    /// Not fatal if it fails, like blocking: a kernel that will not take these programs is a machine that
    /// cannot intercept, which is a reason to say so rather than a reason to stop watching.
    pub fn attach(
        ebpf: &mut Ebpf,
        cgroup: &Path,
        database: &Path,
        certificates: &Path,
        machine: &str,
    ) -> Result<Self> {
        let keys = Authority::keys_for(database);
        let authority = Authority::open(&keys, certificates, machine).with_context(|| {
            format!(
                "preparing the certificate authority: its keys in {}, its certificate in {}",
                keys.display(),
                certificates.display()
            )
        })?;
        let proxy = Proxy::new(authority).context("preparing the proxy")?;

        let file = std::fs::File::open(cgroup)
            .with_context(|| format!("opening {} to attach to it", cgroup.display()))?;
        for name in ["redirect4", "redirect6"] {
            let program: &mut CgroupSockAddr = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("the compiled program has no {name} function"))?
                .try_into()?;
            program.load().map_err(explain)?;
            attach_one(program, &file, name)?;
        }
        let ops: &mut SockOps = ebpf
            .program_mut("redirect_ops")
            .ok_or_else(|| anyhow!("the compiled program has no redirect_ops function"))?
            .try_into()?;
        ops.load().map_err(explain)?;
        ops.attach(&file, CgroupAttachMode::AllowMultiple)
            .or_else(|_| ops.attach(&file, CgroupAttachMode::Single))
            .context(
                "attaching the program that remembers where a redirected connection was going. Without it \
                 the proxy has no way to ask, so nothing is redirected.",
            )?;

        Ok(Self {
            agents: take(ebpf, "REDIRECT_AGENTS")?,
            ports: take(ebpf, "REDIRECT_PORTS")?,
            to: Array::try_from(
                ebpf.take_map("REDIRECT_TO")
                    .ok_or_else(|| anyhow!("the compiled program has no REDIRECT_TO map"))?,
            )?,
            proxy: Arc::new(proxy),
            running: None,
            scoped: std::collections::HashSet::new(),
            port: None,
        })
    }

    /// Brings the kernel into line with what somebody configured.
    ///
    /// `identity` turns an agent's name into the number the kernel knows it by. It is the blocking module's
    /// numbering, shared on purpose: two numberings for one agent would be a scope that named a different
    /// process from the rules.
    pub fn apply(
        &mut self,
        intercept: &Intercept,
        mocks: Vec<Mock>,
        mut identity: impl FnMut(&str) -> u32,
    ) -> Result<bool> {
        self.proxy.set_spared(intercept.never.clone());
        self.proxy.set_mocks(mocks);

        if self.running.as_ref() == Some(intercept) {
            return Ok(false);
        }

        let wanted: std::collections::HashSet<u32> = if intercept.running() {
            intercept
                .agents
                .iter()
                .map(|agent| identity(agent))
                .collect()
        } else {
            std::collections::HashSet::new()
        };
        for gone in self.scoped.difference(&wanted) {
            let _ = self.agents.remove(gone);
        }
        for added in wanted.difference(&self.scoped) {
            self.agents
                .insert(added, IN_SCOPE, 0)
                .context("putting an agent into the kernel's interception scope")?;
        }
        self.scoped = wanted;

        // The switch. Zero means nothing is redirected, whatever else the maps say, which is what makes
        // turning it off immediate rather than eventual.
        let port = match (intercept.running(), self.port) {
            (true, Some(port)) => port,
            _ => 0,
        };
        self.to
            .set(PROXY_PORT, port, 0)
            .context("telling the kernel where the proxy is")?;
        if port == 0 {
            let _ = self.ports.remove(&HTTPS);
        } else {
            self.ports
                .insert(HTTPS, IN_SCOPE, 0)
                .context("telling the kernel which port to redirect")?;
        }
        self.running = Some(intercept.clone());
        Ok(true)
    }

    /// Starts the listeners.
    ///
    /// Loopback only, and both families, because a connection redirected from an IPv6 destination arrives at
    /// `::1` and one redirected from IPv4 arrives at `127.0.0.1`. The v6 listener is not fatal: a machine
    /// with IPv6 switched off has no v6 connections to redirect either.
    pub fn listen(
        &mut self,
        wanted: u16,
        originals: BpfHashMap<MapData, u16, Original>,
        sender: &Sender<crate::Message>,
    ) -> Result<u16> {
        let four = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), wanted))
            .with_context(|| {
                format!("listening on 127.0.0.1:{wanted} for redirected connections")
            })?;
        let port = four
            .local_addr()
            .context("asking which port the proxy got")?
            .port();
        let six = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)).ok();

        let originals = Arc::new(std::sync::Mutex::new(originals));
        for listener in [Some(four), six].into_iter().flatten() {
            let proxy = Arc::clone(&self.proxy);
            let originals = Arc::clone(&originals);
            let sender = sender.clone();
            std::thread::Builder::new()
                .name("flowlight-proxy".to_owned())
                .spawn(move || accept(&listener, &proxy, &originals, &sender))
                .context("starting the proxy's listener")?;
        }
        self.port = Some(port);
        Ok(port)
    }
}

/// Accepts connections and hands each to the proxy on a thread of its own.
fn accept(
    listener: &TcpListener,
    proxy: &Arc<Proxy>,
    originals: &Arc<std::sync::Mutex<BpfHashMap<MapData, u16, Original>>>,
    sender: &Sender<crate::Message>,
) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        // The source port is the only handle on which connection this is, and the kernel wrote the
        // destination down against it a moment ago.
        let source = stream.peer_addr().map(|peer| peer.port()).unwrap_or(0);
        let original = originals
            .lock()
            .ok()
            .and_then(|map| map.get(&source, 0).ok())
            .filter(Original::is_set);
        let Some(original) = original else {
            // Something connected to the proxy that the kernel did not redirect. Nothing is relayed, because
            // there is nowhere to relay it to, and nothing is guessed at from a header the client wrote.
            //
            // Said out loud, because the first time this happened it was silent: the program that writes the
            // destination down was firing on the wrong callback, so every redirected connection arrived here
            // with nothing to look up, and the only symptom was a client that could not connect.
            let _ = sender.send(crate::Message::Intercepted(Box::new(Happened {
                tgid: 0,
                decided: Decided::Failed {
                    host: None,
                    why: format!(
                        "a connection from 127.0.0.1:{source} arrived at the proxy with no record of where \
                         it was going, so it could not be sent anywhere"
                    ),
                },
            })));
            flowlight_proxy::serve::refuse(
                stream,
                "this connection was not redirected by Flowlight, so there is nothing to send it on to",
            );
            continue;
        };
        let _ = originals.lock().map(|mut map| map.remove(&source));

        let proxy = Arc::clone(proxy);
        let sender = sender.clone();
        let _ = std::thread::Builder::new()
            .name("flowlight-intercept".to_owned())
            .spawn(move || {
                let decided = proxy.handle(stream, reached_of(&original));
                let _ = sender.send(crate::Message::Intercepted(Box::new(Happened {
                    tgid: original.tgid,
                    decided,
                })));
            });
    }
}

/// Where a connection was going, as the proxy wants it.
fn reached_of(original: &Original) -> Reached {
    let address = if original.family == flowlight_common::connection::AF_INET {
        let [a, b, c, d] = [
            original.address[0],
            original.address[1],
            original.address[2],
            original.address[3],
        ];
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    } else {
        IpAddr::V6(Ipv6Addr::from(original.address))
    };
    Reached {
        address,
        port: original.port,
    }
}

/// Attaches one of the redirect programs, trying the mode a modern kernel wants first.
///
/// The same dance as the blocking programs: `bpf_link_create` refuses `BPF_F_ALLOW_MULTI` because a link is
/// already multi, and a kernel old enough to need prog-attach needs the flag. So: try one, fall back.
fn attach_one(program: &mut CgroupSockAddr, file: &std::fs::File, name: &str) -> Result<()> {
    program
        .attach(file, CgroupAttachMode::AllowMultiple)
        .or_else(|_| program.attach(file, CgroupAttachMode::Single))
        .with_context(|| format!("attaching {name} to the cgroup"))?;
    Ok(())
}

/// Takes one of the maps out of the loaded program.
fn take<K: aya::Pod, V: aya::Pod>(
    ebpf: &mut Ebpf,
    name: &str,
) -> Result<BpfHashMap<MapData, K, V>> {
    let map = ebpf
        .take_map(name)
        .ok_or_else(|| anyhow!("the compiled program has no {name} map"))?;
    Ok(BpfHashMap::try_from(map)?)
}

/// What a load failure means, in words.
fn explain(err: aya::programs::ProgramError) -> anyhow::Error {
    anyhow!(
        "{err}. Redirecting a connection needs a kernel that takes cgroup/connect and sock_ops programs, \
         which is 4.17 and later, and a cgroup v2 hierarchy this process may attach to."
    )
}

/// Whether a port is one a proxy may be asked to listen on.
pub fn sensible_port(port: u16) -> Result<u16> {
    if port != 0 && port < 1024 {
        bail!(
            "{port} is a privileged port. The proxy listens on loopback and is reached only by the kernel's \
             own redirect, so there is no reason for it to be one."
        );
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original(family: u16, address: [u8; 16], port: u16) -> Original {
        Original {
            address,
            tgid: 42,
            agent: 1,
            port,
            family,
        }
    }

    #[test]
    fn a_four_byte_address_comes_back_as_the_address_it_was() {
        let mut address = [0_u8; 16];
        address[..4].copy_from_slice(&[93, 184, 216, 34]);
        let reached = reached_of(&original(
            flowlight_common::connection::AF_INET,
            address,
            443,
        ));
        assert_eq!(reached.address.to_string(), "93.184.216.34");
        assert_eq!(reached.port, 443);
    }

    #[test]
    fn a_sixteen_byte_address_comes_back_as_one_too() {
        let mut address = [0_u8; 16];
        address[0] = 0x20;
        address[1] = 0x01;
        address[15] = 1;
        let reached = reached_of(&original(
            flowlight_common::connection::AF_INET6,
            address,
            8443,
        ));
        assert_eq!(reached.address.to_string(), "2001::1");
        assert_eq!(reached.port, 8443);
    }

    /// An empty slot is not a destination. Read as one it would be a connection to 0.0.0.0:0.
    #[test]
    fn an_empty_slot_says_it_is_empty() {
        assert!(!Original::empty().is_set());
        assert!(original(flowlight_common::connection::AF_INET, [0; 16], 443).is_set());
        assert!(!original(flowlight_common::connection::AF_INET, [0; 16], 0).is_set());
    }

    /// What Flowlight did is kept; what it merely passed on is not, or a note per connection would bury the
    /// ones that matter.
    #[test]
    fn only_what_flowlight_did_is_worth_keeping() {
        let kept = |decided| Happened { tgid: 1, decided }.is_worth_keeping();
        assert!(kept(Decided::Answered {
            host: "x".to_owned(),
            rules: vec![1],
            refusal: false
        }));
        assert!(kept(Decided::Failed {
            host: None,
            why: "no".to_owned()
        }));
        assert!(!kept(Decided::Passed { host: None }));
        assert!(!kept(Decided::Forwarded {
            host: "x".to_owned(),
            requests: 3
        }));
    }

    /// A refusal and a stand-in are recorded under different names, because they are not the same thing to
    /// read in a log six weeks later.
    #[test]
    fn a_refusal_and_a_mock_are_recorded_differently() {
        let describe = |refusal| {
            Happened {
                tgid: 1,
                decided: Decided::Answered {
                    host: "api.example.com".to_owned(),
                    rules: vec![4, 5],
                    refusal,
                },
            }
            .describe()
        };
        let (kind, subject, detail) = describe(false);
        assert_eq!(kind, "mocked");
        assert_eq!(subject, "api.example.com");
        assert!(detail.contains("rather than by the server"));
        assert!(detail.contains("4, 5"));
        assert_eq!(describe(true).0, "refused-request");
    }

    #[test]
    fn a_privileged_port_is_refused() {
        assert!(sensible_port(80).is_err());
        assert!(sensible_port(7891).is_ok());
        // Zero means "any", which the listener turns into whatever it was given.
        assert_eq!(sensible_port(0).unwrap(), 0);
    }
}
