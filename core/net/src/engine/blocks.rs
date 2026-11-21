//! Tracker blocking in the engine (W8, part 3a; ADR 0053): what Watch's Kotlin side sets, the one decision every
//! path asks, the answers that carry it to Android's resolver, and the hold of a connection's first bytes until
//! they name it.
//!
//! **The decision** ([`Shared::verdict`]) takes the app, a name, and the path that asks: a lookup, or a
//! connection. A name is blocked only when blocking is on and not paused, the graded table's narrowest row names
//! it ([`crate::blocking::Table::find`]), the row is `block` for this app (its own grade, or the grade Kotlin
//! decided for this app from its code, or kept by an exception), the app is one blocking covers, and the user
//! allowed neither the app nor that row in it. Expiry is checked here, at each decision, on the time since the
//! phone started: no alarm wakes anything. The same rows are blocked in every app, the tracker's own company's
//! included (decision 2): nothing here reads who owns an app.
//!
//! **The user's tool** is never blocked by its connections, whose names may be any popular host as a cover: only
//! its own lookups, by DNS alone, and only where the user turned that on (decision 5). Flows Android named no app
//! for are never blocked.
//!
//! **Android's cache** keeps one answer per question for every app of a network. So a blocked lookup gets "no
//! data" kept for no time ([`crate::answers::blocked`]), and while blocking is on every answer for a name a row
//! grades `block` or `code` goes with a time to live of 0 too, whichever app asked: no app's answer reaches
//! another's lookup.
//!
//! **A connection's first bytes** are held while they read as an unfinished TLS hello or plain HTTP request head,
//! at most [`crate::tls::MAX_HELLO`] bytes and [`HOLD`], and nothing of them is written upstream, or to the user's
//! tool, until the name they carry is decided ([`Gate`]). A protocol in which the server speaks first sends
//! nothing first, and never waits. A flow whose name a row names is decided again at each read after, so that a
//! block set again, or an allowance that ran out, resets it at its next byte (an HTTP/2 connection pools many
//! requests).

use super::{Counters, Shared, lock};
use crate::blocking::{Grade, HttpHost, Table, http_host};
use crate::owners::NetworkKind;
use crate::tls::{self, ServerName};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// How long a connection's first bytes are held at most while they still read as an unfinished hello or request
/// head: a client sends a whole `ClientHello` at once, two segments for a post-quantum one, so a hold this long
/// means the rest is not coming, and the bytes go on unread.
pub const HOLD: Duration = Duration::from_secs(1);

/// The most addresses kept for blocking by address, as [`crate::names::CAPACITY`] keeps names.
const TIES: usize = 8_192;

/// The most apps and rows counted at once for "Now": far above a phone's apps times the rows they reach.
const TALLIES: usize = 4_096;

/// What Watch's Kotlin side sets for tracker blocking, whole each time (ADR 0053), and keeps for the engines to
/// come, as the chain is.
#[derive(Clone, Debug, Default)]
pub struct BlockSetting {
    /// Whether the user turned blocking on.
    pub on: bool,
    /// The graded table of the data pack (`blocking/hosts.tsv`), with any debug build's entry for the lab's names.
    pub table: Option<Arc<Table>>,
    /// The apps blocking covers, by UID: the apps the user installed, without the browsers unless the user
    /// included them, and never the user's tool, Watch, Play services or the system's.
    pub covered: Vec<u32>,
    /// Whether the user's tool's own lookups are blocked by DNS, off by default.
    pub tool_dns: bool,
    /// For each app, the rows whose grade its code decides, and the rows an exception keeps for it.
    pub graded: Vec<(u32, usize, Grade)>,
    /// Until when, in time since the phone started, the global pause lasts; zero for none.
    pub paused_until: Duration,
    /// The apps the user allowed, each until when, in time since the phone started ([`Duration::MAX`] until the
    /// user blocks it again).
    pub apps_allowed: Vec<(u32, Duration)>,
    /// The rows the user allowed in one app.
    pub entries_allowed: Vec<(u32, usize)>,
}

/// Which path asks for a decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Path {
    /// A lookup to Watch's DNS address.
    Lookup,
    /// A connection: its hello, its request's host, its stand-in's name or its address.
    Connection,
}

/// What blocking counts for one app and one row, for "Now", in memory only: lookups answered empty apart from
/// connections refused (decision 7), and since when, on the wall clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// Lookups answered "no data".
    pub lookups: u64,
    /// Connections refused: by their hello, request, stand-in or address, TCP and QUIC.
    pub connections: u64,
    /// The first of them, in milliseconds since 1970.
    pub since_ms: u64,
}

/// An address an answer Watch passed gave a name: whether every name given it while held was one a row grades
/// `block` or `code`, the row of the last such name, and until when it is held.
#[derive(Clone, Copy, Debug)]
struct Tie {
    blocked_only: bool,
    entry: usize,
    until: Instant,
}

/// The engine's state of blocking.
#[derive(Default)]
pub(super) struct Blocks {
    setting: BlockSetting,
    covered: HashSet<u32>,
    graded: HashMap<(u32, usize), Grade>,
    apps: HashMap<u32, Duration>,
    entries: HashSet<(u32, usize)>,
    tallies: HashMap<(u32, usize), Tally>,
    ties: HashMap<IpAddr, Tie>,
}

impl Blocks {
    fn set(&mut self, setting: BlockSetting) {
        self.covered = setting.covered.iter().copied().collect();
        self.graded = setting
            .graded
            .iter()
            .map(|&(uid, entry, grade)| ((uid, entry), grade))
            .collect();
        self.apps = setting.apps_allowed.iter().copied().collect();
        self.entries = setting.entries_allowed.iter().copied().collect();
        // Another table's rows are other rows: what was counted and tied by the old one's places goes.
        let same_table = match (&self.setting.table, &setting.table) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b) || a == b,
            (None, None) => true,
            _ => false,
        };
        if !same_table {
            self.tallies.clear();
            self.ties.clear();
        }
        self.setting = setting;
    }

    /// The row of `entry`'s grade for `uid`.
    fn grade(&self, uid: u32, entry: usize) -> Option<Grade> {
        let table = self.setting.table.as_ref()?;
        let own = table.entries().get(entry)?.grade;
        Some(self.graded.get(&(uid, entry)).copied().unwrap_or(own))
    }

    /// Whether the row `entry` is blocked for `uid` on `path` now, the user's tool being `tool`.
    fn blocks(&self, uid: u32, entry: usize, path: Path, tool: Option<u32>, now: Duration) -> bool {
        let s = &self.setting;
        if !s.on || now < s.paused_until {
            return false;
        }
        if Some(uid) == tool {
            if !(path == Path::Lookup && s.tool_dns) {
                return false;
            }
        } else if !self.covered.contains(&uid) {
            return false;
        }
        if self.grade(uid, entry) != Some(Grade::Block) {
            return false;
        }
        if self.apps.get(&uid).is_some_and(|until| now < *until) {
            return false;
        }
        !self.entries.contains(&(uid, entry))
    }

    /// The row that names `name`, if blocking is on with a table.
    fn row(&self, name: &str) -> Option<usize> {
        if !self.setting.on {
            return None;
        }
        self.setting.table.as_ref()?.find(name)
    }

    /// Whether a row that may block names `name`: `block`, or `code`, which blocks in some apps.
    fn blockable(&self, name: &str) -> Option<usize> {
        let entry = self.row(name)?;
        let grade = self.setting.table.as_ref()?.entries().get(entry)?.grade;
        (grade != Grade::Keep).then_some(entry)
    }

    fn tally(&mut self, uid: u32, entry: usize, lookup: bool, wall_ms: u64) {
        if self.tallies.len() >= TALLIES && !self.tallies.contains_key(&(uid, entry)) {
            return;
        }
        let tally = self.tallies.entry((uid, entry)).or_insert(Tally {
            since_ms: wall_ms,
            ..Tally::default()
        });
        if lookup {
            tally.lookups += 1;
        } else {
            tally.connections += 1;
        }
    }
}

impl Shared {
    /// Sets blocking as Watch's Kotlin side last said ([`BlockSetting`]).
    pub(super) fn set_blocking(&self, setting: BlockSetting) {
        lock(&self.blocks).set(setting);
        self.blocking_set.fetch_add(1, Ordering::Release);
    }

    /// What blocking is set to now, for the engine that comes next.
    pub(super) fn blocking(&self) -> BlockSetting {
        lock(&self.blocks).setting.clone()
    }

    /// Whether blocking is on, with a table: then connections are read for their names.
    pub(super) fn blocking_on(&self) -> bool {
        let blocks = lock(&self.blocks);
        blocks.setting.on && blocks.setting.table.is_some()
    }

    /// The user's tool's UID, while a chain is on.
    fn tool_uid(&self) -> Option<u32> {
        self.chain().map(|chain| chain.tool)
    }

    /// The row that blocks `name` for the app `uid` on `path` now, if one does (the module's comment).
    pub(super) fn verdict(&self, uid: Option<u32>, name: &str, path: Path) -> Option<usize> {
        let uid = uid?;
        let tool = self.tool_uid();
        let now = self.clock.since_boot();
        let blocks = lock(&self.blocks);
        let entry = blocks.row(name)?;
        blocks.blocks(uid, entry, path, tool, now).then_some(entry)
    }

    /// Whether the row `entry` still blocks a connection of `uid`, decided again at a flow's later bytes.
    pub(super) fn still_blocks(&self, uid: u32, entry: usize) -> bool {
        let tool = self.tool_uid();
        let now = self.clock.since_boot();
        lock(&self.blocks).blocks(uid, entry, Path::Connection, tool, now)
    }

    /// Counts one lookup answered empty or one connection refused, for the app `uid` and the row `entry`.
    pub(super) fn count_block(&self, uid: Option<u32>, entry: usize, lookup: bool) {
        Counters::add(
            if lookup {
                &self.counters.blocked_lookups
            } else {
                &self.counters.blocked_connections
            },
            1,
        );
        if let Some(uid) = uid {
            let wall = self.clock.wall_ms();
            lock(&self.blocks).tally(uid, entry, lookup, wall);
        }
    }

    /// The answer to a lookup whose question a row blocks for its app: "no data", kept for no time, with the lookup
    /// counted; `None` for a lookup blocking lets through, or a message that is no query.
    pub(super) fn lookup_blocked(&self, uid: Option<u32>, query: &[u8]) -> Option<Vec<u8>> {
        let question = crate::answers::question(query)?;
        let entry = self.verdict(uid, &question.name, Path::Lookup)?;
        let answer = crate::answers::blocked(query, &question)?;
        self.count_block(uid, entry, true);
        Some(answer)
    }

    /// An answer to `uid`'s `query` as blocking passes it on: "no data" in its place where a row blocks any name of
    /// its CNAME chain for this app, which closes CNAME cloaking; otherwise the answer itself, with every time to
    /// live 0 where a row that may block names any name of it, so that Android's resolver keeps it for no app.
    pub(super) fn answer_blocked(&self, uid: Option<u32>, query: &[u8], answer: &mut Vec<u8>) {
        let Some(chain) = crate::dns::chain(answer) else {
            return;
        };
        let (tool, now) = (self.tool_uid(), self.clock.since_boot());
        let (blocked, blockable) = {
            let blocks = lock(&self.blocks);
            let blocked = uid.and_then(|uid| {
                chain.iter().find_map(|name| {
                    let entry = blocks.row(name)?;
                    blocks
                        .blocks(uid, entry, Path::Lookup, tool, now)
                        .then_some(entry)
                })
            });
            let blockable = chain.iter().any(|name| blocks.blockable(name).is_some());
            (blocked, blockable)
        };
        // The answer's own ID and question stand for the query where the caller has none at hand.
        let from_answer;
        let query = if crate::answers::question(query).is_some() {
            query
        } else {
            from_answer = as_query(answer);
            &from_answer
        };
        if let Some(entry) = blocked
            && let Some(question) = crate::answers::question(query)
            && let Some(empty) = crate::answers::blocked(query, &question)
        {
            self.count_block(uid, entry, true);
            *answer = empty;
            return;
        }
        if blockable {
            crate::dns::uncache(answer);
        }
    }

    /// Notes the addresses an answer Watch passed on from Android's resolver gave `names` (the question and its
    /// CNAME chain), for blocking by address: an address stays tied to blocked names alone only while every name
    /// given it, as long as it is held, is one a row grades `block` or `code`.
    pub(super) fn tie(&self, names: &[String], addresses: &[(IpAddr, u32)]) {
        let mut blocks = lock(&self.blocks);
        if !blocks.setting.on {
            return;
        }
        let entry = names.iter().find_map(|name| blocks.blockable(name));
        let now = Instant::now();
        for &(address, ttl) in addresses {
            let keep = Duration::from_secs(u64::from(ttl))
                .clamp(crate::names::MIN_KEEP, crate::names::MAX_KEEP);
            let until = now + keep;
            let alive = blocks
                .ties
                .get(&address)
                .filter(|tie| tie.until > now)
                .copied();
            let tie = match (entry, alive) {
                (Some(entry), Some(old)) => Tie {
                    blocked_only: old.blocked_only,
                    entry,
                    until: until.max(old.until),
                },
                (Some(entry), None) => Tie {
                    blocked_only: true,
                    entry,
                    until,
                },
                (None, Some(old)) => Tie {
                    blocked_only: false,
                    until: until.max(old.until),
                    ..old
                },
                // An address no blocked name was ever given needs no tie: it is never blocked.
                (None, None) => {
                    blocks.ties.remove(&address);
                    continue;
                }
            };
            if blocks.ties.len() >= TIES && !blocks.ties.contains_key(&address) {
                blocks.ties.retain(|_, tie| tie.until > now);
                if blocks.ties.len() >= TIES {
                    // Full: no new tie, so no block by this address, never a wrong one.
                    continue;
                }
            }
            blocks.ties.insert(address, tie);
        }
    }

    /// The row that blocks a connection of `uid` to `address` by its address alone (decision 4): only where an
    /// answer Watch passed, still held, tied the address to blocked names alone, and never inside a network the
    /// organisation table does not name as a company's own (a CDN, a cloud or a host sells room to others,
    /// ADR 0036). The connection is then asked of Android first, and refused before anything leaves.
    pub(super) fn address_verdict(&self, uid: Option<u32>, address: IpAddr) -> Option<usize> {
        let tie = self.address_tie(address)?;
        let uid = uid?;
        let (tool, now) = (self.tool_uid(), self.clock.since_boot());
        lock(&self.blocks)
            .blocks(uid, tie, Path::Connection, tool, now)
            .then_some(tie)
    }

    /// The row of an address tied to blocked names alone, outside any network that hosts others, while blocking
    /// is on: a connection to it waits for Android to name its app before anything leaves.
    pub(super) fn address_tie(&self, address: IpAddr) -> Option<usize> {
        let tie = {
            let blocks = lock(&self.blocks);
            if !blocks.setting.on {
                return None;
            }
            blocks
                .ties
                .get(&address)
                .filter(|tie| tie.blocked_only && tie.until > Instant::now())
                .map(|tie| tie.entry)?
        };
        let (network, _) = self.organisation(address)?;
        (network.kind == NetworkKind::Own).then_some(tie)
    }

    /// A relayed flow `id` that blocking refused by the row `entry`, at its hello, its request's host, or a later
    /// byte: blocked in the log, the flows kept and the counters, with the row's SDK; its last segment is written
    /// as any flow's when its rewriting goes.
    pub(super) fn blocked_flow(&self, id: u64, entry: usize) {
        self.log_now();
        let sdk = self
            .row_sdk(entry)
            .map(|sdk| Box::new(super::BlockedBy { sdk }));
        let uid = {
            let mut live = lock(&self.live);
            let Some(live) = live.get_mut(&id) else {
                return;
            };
            live.flow.outcome = super::Outcome::Blocked;
            live.flow.blocked.clone_from(&sdk);
            live.flow.uid
        };
        if let Some(flow) = lock(&self.flows).iter_mut().rev().find(|f| f.id == id) {
            flow.outcome = super::Outcome::Blocked;
            flow.blocked.clone_from(&sdk);
        }
        self.count_block(uid, entry, false);
    }

    /// What blocking counted in memory, for "Now": each app's rows with their tallies, by the row's host.
    pub(super) fn blocked_tallies(&self) -> Vec<(u32, String, Tally)> {
        let blocks = lock(&self.blocks);
        let Some(table) = blocks.setting.table.as_ref() else {
            return Vec::new();
        };
        let mut out: Vec<(u32, String, Tally)> = blocks
            .tallies
            .iter()
            .filter_map(|(&(uid, entry), &tally)| {
                Some((uid, table.entries().get(entry)?.host.clone(), tally))
            })
            .collect();
        out.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        out
    }

    /// Forgets the tallies, with the live view (ADR 0047's profile clears it).
    pub(super) fn clear_blocked(&self) {
        lock(&self.blocks).tallies.clear();
    }

    /// The SDK of the row `entry`, which a blocked flow's records carry.
    pub(super) fn row_sdk(&self, entry: usize) -> Option<String> {
        let blocks = lock(&self.blocks);
        Some(
            blocks
                .setting
                .table
                .as_ref()?
                .entries()
                .get(entry)?
                .sdk
                .clone(),
        )
    }

    /// A gate for a connection of `uid` (the module's comment), the user's tool's excepted, whose flows are never
    /// read for a block: none for a flow of no app. Whether it holds is decided at its first bytes.
    pub(super) fn gate(&self, uid: Option<u32>) -> Option<Gate> {
        let uid = uid?;
        if self.tool_uid() == Some(uid) || !self.blocking_on() {
            return None;
        }
        Some(Gate::new(uid))
    }
}

/// The query a response answers, from its own ID, flags and question: what "no data" is built from where the
/// query itself is not at hand. Empty for a response with no question that can be read.
fn as_query(answer: &[u8]) -> Vec<u8> {
    let Some((_, after)) = crate::dns::read_name(answer, 12) else {
        return Vec::new();
    };
    let Some(mut query) = answer.get(..after + 4).map(<[u8]>::to_vec) else {
        return Vec::new();
    };
    query[2] &= 0x7f;
    query[3] = 0;
    query[4..12].copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    query
}

/// What a gate says of a connection's next bytes.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Step {
    /// Hold them: they are kept in the gate, and nothing is written.
    Hold,
    /// Write these, the bytes held and the last read with them, and read on.
    Release(Vec<u8>),
    /// Write the bytes just read as they are.
    Through,
    /// Refuse the connection: the row that blocks it.
    Block(usize),
}

/// The hold of one connection's first bytes, and its row once its name was read.
pub(super) struct Gate {
    uid: u32,
    /// The bytes held, while the start still reads as an unfinished hello or request head.
    held: Vec<u8>,
    /// Until when the bytes are held.
    until: Option<tokio::time::Instant>,
    /// Whether the start is still read for a name.
    reading: bool,
    /// The row that names the flow, once a name was read: decided again at each later read.
    entry: Option<usize>,
}

impl Gate {
    fn new(uid: u32) -> Self {
        Self {
            uid,
            held: Vec::new(),
            until: None,
            reading: true,
            entry: None,
        }
    }

    /// Until when the gate holds what it holds, if it holds anything.
    pub(super) fn until(&self) -> Option<tokio::time::Instant> {
        self.until.filter(|_| !self.held.is_empty())
    }

    /// The row that named the flow, once its name was read.
    pub(super) fn entry(&self) -> Option<usize> {
        self.entry
    }

    /// The hold ran out: what it held goes on unread.
    pub(super) fn ran_out(&mut self) -> Vec<u8> {
        self.reading = false;
        self.until = None;
        std::mem::take(&mut self.held)
    }

    /// Reads the app's next `bytes`.
    pub(super) fn feed(&mut self, shared: &Shared, bytes: &[u8]) -> Step {
        if !self.reading {
            return match self.entry {
                Some(entry) if shared.still_blocks(self.uid, entry) => Step::Block(entry),
                _ => Step::Through,
            };
        }
        let holding = !self.held.is_empty();
        if holding {
            self.held.extend_from_slice(bytes);
        }
        let start: &[u8] = if holding { &self.held } else { bytes };
        let name = match read_name(start) {
            Read::Incomplete if start.len() < tls::MAX_HELLO => {
                if !holding {
                    self.held = bytes.to_vec();
                    self.until = Some(tokio::time::Instant::now() + HOLD);
                }
                return Step::Hold;
            }
            Read::Incomplete | Read::None => None,
            Read::Found(name) => Some(name),
        };
        self.reading = false;
        self.until = None;
        let held = std::mem::take(&mut self.held);
        if let Some(name) = name {
            let tool = shared.tool_uid();
            let now = shared.clock.since_boot();
            let blocks = lock(&shared.blocks);
            if let Some(entry) = blocks.row(&name) {
                self.entry = Some(entry);
                if blocks.blocks(self.uid, entry, Path::Connection, tool, now) {
                    return Step::Block(entry);
                }
            }
        }
        if holding {
            Step::Release(held)
        } else {
            Step::Through
        }
    }
}

/// What the start of a stream names.
enum Read {
    Found(String),
    None,
    Incomplete,
}

/// The name a stream's start carries: a TLS hello's server name, or a plain HTTP request's `Host`.
fn read_name(start: &[u8]) -> Read {
    match start.first() {
        None => Read::Incomplete,
        Some(22) => match tls::server_name(start) {
            ServerName::Found(hello) => Read::Found(hello.name),
            ServerName::None => Read::None,
            ServerName::Incomplete => Read::Incomplete,
        },
        Some(b'A'..=b'Z') => match http_host(start) {
            HttpHost::Found(host) => Read::Found(host),
            HttpHost::None => Read::None,
            HttpHost::Incomplete => Read::Incomplete,
        },
        Some(_) => Read::None,
    }
}

/// The hold of a QUIC flow's first datagrams while its Initial packets read as an unfinished `ClientHello`
/// (decision 4: a post-quantum hello spans two datagrams): nothing of them leaves until its name is decided.
#[derive(Default)]
pub(super) struct QuicGate {
    /// The datagrams held, in order.
    pub(super) held: Vec<HeldDatagram>,
    /// Until when they are held.
    pub(super) until: Option<Instant>,
    /// The row that names the flow, once its hello, its stand-in's name or its address named it.
    pub(super) entry: Option<usize>,
    /// Whether the flow was refused: what the app sends it after is dropped, and the app told so.
    pub(super) refused: bool,
    /// Whether the refusal is in the flow's records and the tallies.
    pub(super) recorded: bool,
}

/// A datagram a [`QuicGate`] holds: its payload, what a router quotes of it, its hop limit and its length on the
/// tunnel.
pub(super) struct HeldDatagram {
    pub(super) payload: Vec<u8>,
    pub(super) sent: Option<crate::packet::Sent>,
    pub(super) hops: u8,
    pub(super) length: usize,
}

impl Shared {
    /// A gate for a new UDP flow of `uid` to `address`, a stand-in for `name` if it is one ([`QuicGate`]): none
    /// for a flow of no app or of the user's tool, or while blocking is off. A flow its stand-in's name or its
    /// address blocks is refused from its first datagram, before anything leaves.
    pub(super) fn quic_gate(
        &self,
        uid: Option<u32>,
        address: std::net::SocketAddr,
        name: Option<&str>,
    ) -> Option<Box<QuicGate>> {
        let id = uid?;
        if self.tool_uid() == Some(id) || !self.blocking_on() {
            return None;
        }
        let mut gate = QuicGate::default();
        let refused = match name {
            Some(name) => self.verdict(uid, name, Path::Connection),
            None => self.address_verdict(uid, address.ip()).inspect(|_| {
                Counters::add(&self.counters.blocked_addresses, 1);
            }),
        };
        if let Some(entry) = refused {
            gate.entry = Some(entry);
            gate.refused = true;
        }
        Some(Box::new(gate))
    }

    /// The row that names a QUIC hello's `name`, and whether it blocks the flow of `uid` now.
    pub(super) fn quic_verdict(&self, uid: Option<u32>, name: &str) -> Option<(usize, bool)> {
        let uid = uid?;
        let tool = self.tool_uid();
        let now = self.clock.since_boot();
        let blocks = lock(&self.blocks);
        let entry = blocks.row(name)?;
        Some((
            entry,
            blocks.blocks(uid, entry, Path::Connection, tool, now),
        ))
    }
}

/// The most datagrams held for one QUIC flow: a hello spans two, and Chrome's with its padding no more than four.
pub(super) const QUIC_HELD: usize = 4;

#[cfg(test)]
mod tests {
    use super::super::clock::ManualClock;
    use super::super::tests::{dns_answer, shared};
    use super::*;
    use crate::blocking::tests::table;

    /// An app the user installed, which blocking covers, another, and the user's tool.
    const APP: u32 = 10_101;
    const OTHER: u32 = 10_102;
    const TOOL: u32 = 10_200;
    /// An app blocking does not cover: a browser, or a preinstalled app.
    const BROWSER: u32 = 10_300;

    /// The engine's state, blocking on with the rows given, covering [`APP`] and [`OTHER`], at a clock of its own.
    fn blocking(rows: &[(&str, &str)]) -> (Shared, Arc<ManualClock>) {
        let clock = ManualClock::at(1_794_873_600_000);
        let mut shared = shared();
        shared.clock = clock.clone();
        shared.set_blocking(BlockSetting {
            on: true,
            table: Some(Arc::new(table(rows))),
            covered: vec![APP, OTHER],
            ..BlockSetting::default()
        });
        (shared, clock)
    }

    fn set(shared: &Shared, change: impl FnOnce(&mut BlockSetting)) {
        let mut setting = shared.blocking();
        change(&mut setting);
        shared.set_blocking(setting);
    }

    const ROWS: &[(&str, &str)] = &[
        ("app-measurement.com", "block"),
        ("googleads.g.doubleclick.net", "block"),
        ("graph.facebook.com", "code"),
        ("firebaseinstallations.googleapis.com", "keep"),
    ];

    fn query(name: &str, kind: u16) -> Vec<u8> {
        let mut q = vec![0x77, 0x01, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(u8::try_from(label.len()).unwrap_or(0));
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&kind.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    /// A `block` row is blocked in every app blocking covers, whoever made the app (decision 2: the engine never
    /// reads who owns an app, so an app of the tracker's own company is one more covered app); a `keep` row in
    /// none; a `code` row only where Kotlin graded it `block` for the app; nothing in an app it does not cover.
    #[test]
    fn the_same_rows_are_blocked_in_every_covered_app() {
        let (shared, _) = blocking(ROWS);
        let blocked = |uid, name: &str| shared.verdict(Some(uid), name, Path::Connection).is_some();
        for uid in [APP, OTHER] {
            assert!(blocked(uid, "app-measurement.com"));
            assert!(blocked(uid, "pagead.googleads.g.doubleclick.net"));
            assert!(!blocked(uid, "firebaseinstallations.googleapis.com"));
            assert!(
                !blocked(uid, "graph.facebook.com"),
                "a code row is kept until graded"
            );
        }
        assert!(!blocked(BROWSER, "app-measurement.com"));
        assert_eq!(
            shared.verdict(None, "app-measurement.com", Path::Connection),
            None
        );
        let graph = table(ROWS).find("graph.facebook.com").unwrap_or(usize::MAX);
        set(&shared, |s| {
            s.graded = vec![(APP, graph, Grade::Block), (OTHER, 0, Grade::Keep)];
        });
        assert!(blocked(APP, "graph.facebook.com"));
        assert!(!blocked(OTHER, "graph.facebook.com"));
        assert!(
            !blocked(OTHER, "app-measurement.com"),
            "an exception keeps the row for its app"
        );
        set(&shared, |s| s.on = false);
        assert!(!blocked(APP, "app-measurement.com"));
    }

    /// The user's tool is never blocked by its connections; its lookups only by DNS, and only with the option.
    #[test]
    fn the_tools_connections_never_and_its_lookups_only_with_the_option() {
        let (shared, _) = blocking(ROWS);
        *lock(&shared.chain) = Some(Arc::new(super::super::Chain {
            proxy: std::net::SocketAddr::from(([127, 0, 0, 1], 10_808)),
            credentials: None,
            tool: TOOL,
            apps: None,
            udp: true,
            log_destinations: false,
        }));
        // Even were Kotlin to list it as covered.
        set(&shared, |s| s.covered.push(TOOL));
        assert_eq!(
            shared.verdict(Some(TOOL), "app-measurement.com", Path::Connection),
            None
        );
        assert_eq!(
            shared.verdict(Some(TOOL), "app-measurement.com", Path::Lookup),
            None
        );
        assert!(
            shared.gate(Some(TOOL)).is_none(),
            "its connections are never held"
        );
        set(&shared, |s| s.tool_dns = true);
        assert!(
            shared
                .verdict(Some(TOOL), "app-measurement.com", Path::Lookup)
                .is_some()
        );
        assert_eq!(
            shared.verdict(Some(TOOL), "app-measurement.com", Path::Connection),
            None
        );
    }

    /// An allowance runs out at a decision, with no alarm: an app allowed for an hour is blocked again after it, one
    /// allowed until blocked again is not; one row allowed in one app leaves its other rows blocked; and a pause
    /// lifts every block until it ends.
    #[test]
    fn allowances_and_the_pause_end_at_a_decision() {
        let (shared, clock) = blocking(ROWS);
        let now = shared.clock.since_boot();
        let hour = Duration::from_secs(3_600);
        set(&shared, |s| {
            s.apps_allowed = vec![(APP, now + hour), (OTHER, Duration::MAX)];
        });
        let blocked = |uid| {
            shared
                .verdict(Some(uid), "app-measurement.com", Path::Lookup)
                .is_some()
        };
        assert!(!blocked(APP) && !blocked(OTHER));
        clock.pass(3_599_000);
        assert!(!blocked(APP));
        clock.pass(1_000);
        assert!(blocked(APP), "the hour ran out");
        assert!(!blocked(OTHER));
        let measurement = table(ROWS)
            .find("app-measurement.com")
            .unwrap_or(usize::MAX);
        set(&shared, |s| {
            s.apps_allowed.clear();
            s.entries_allowed = vec![(APP, measurement)];
        });
        assert!(!blocked(APP));
        assert!(
            shared
                .verdict(Some(APP), "googleads.g.doubleclick.net", Path::Lookup)
                .is_some()
        );
        let now = shared.clock.since_boot();
        set(&shared, |s| s.paused_until = now + Duration::from_secs(600));
        assert!(!blocked(OTHER));
        clock.pass(600_000);
        assert!(blocked(OTHER), "the pause ended");
    }

    /// Two apps, one name, within a second: the blocked one gets "no data" kept for no time, the allowed one the
    /// answer, with every time to live 0, so that Android's one cache per network carries neither to the other
    /// (decision 3); a name no row may block keeps its own.
    #[test]
    fn two_apps_one_name_each_gets_its_own_answer_kept_for_no_time() {
        let (shared, _) = blocking(ROWS);
        set(&shared, |s| s.apps_allowed = vec![(OTHER, Duration::MAX)]);
        let q = query("app-measurement.com", 1);
        let Some(empty) = shared.lookup_blocked(Some(APP), &q) else {
            unreachable!("blocked")
        };
        assert_eq!(empty[6..10], [0, 0, 0, 1], "no answer, an SOA");
        assert_eq!(shared.lookup_blocked(Some(OTHER), &q), None);
        let mut answer = dns_answer("app-measurement.com", [142, 250, 1, 1]);
        shared.answer_blocked(Some(OTHER), &q, &mut answer);
        assert_eq!(
            answer.len(),
            dns_answer("app-measurement.com", [0; 4]).len()
        );
        assert_eq!(
            answer[answer.len() - 10..answer.len() - 6],
            [0, 0, 0, 0],
            "a time to live of 0"
        );
        let mut kept = dns_answer("www.example.com", [93, 184, 216, 34]);
        shared.answer_blocked(Some(APP), &query("www.example.com", 1), &mut kept);
        assert_eq!(
            kept[kept.len() - 10..kept.len() - 6],
            [0, 0, 1, 0x2c],
            "its own time to live"
        );
        // Every record type, HTTPS and SVCB among them.
        for kind in [28, 64, 65, 16, 12] {
            assert!(
                shared
                    .lookup_blocked(Some(APP), &query("x.app-measurement.com", kind))
                    .is_some()
            );
        }
        let tallies = shared.blocked_tallies();
        assert_eq!(tallies.len(), 1);
        assert_eq!(
            (tallies[0].0, tallies[0].2.lookups, tallies[0].2.connections),
            (APP, 6, 0)
        );
    }

    /// A first-party name whose CNAME chain leads to a blocked host gets "no data" in its answer's place, built from
    /// the answer's own question where the query is not at hand (CNAME cloaking, decision 3).
    #[test]
    fn a_cname_to_a_blocked_host_is_blocked() {
        let (shared, _) = blocking(ROWS);
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        m.extend_from_slice(b"\x07metrics\x07example\x03com\x00\x00\x01\x00\x01");
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 23]);
        m.extend_from_slice(b"\x01x\x0fapp-measurement\x03com\x00");
        m.extend_from_slice(&[0xc0, 49, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 142, 250, 1, 1]);
        let mut answer = m.clone();
        shared.answer_blocked(Some(APP), &[], &mut answer);
        assert_eq!(crate::dns::chain(&m).map(|c| c.len()), Some(2));
        assert_eq!(answer[..4], [0x12, 0x34, 0x81, 0x80]);
        assert_eq!(answer[6..10], [0, 0, 0, 1]);
        assert!(crate::dns::response(&answer).is_some_and(|r| r.addresses.is_empty()));
        let mut passed = m.clone();
        shared.answer_blocked(Some(BROWSER), &[], &mut passed);
        assert_eq!(
            passed.len(),
            m.len(),
            "not covered: the answer, kept for no time"
        );
        assert!(
            crate::dns::ttl_offsets(&passed)
                .is_some_and(|o| o.iter().all(|&at| passed[at..at + 4] == [0; 4]))
        );
    }

    /// An address is blocked by itself only while every name an answer Watch passed gave it is a row that may
    /// block, and only inside a company's own network: never a CDN's or a cloud's (decision 4).
    #[test]
    fn an_address_is_blocked_only_where_blocked_names_alone_tied_it_outside_a_cloud() {
        let (mut shared, _) = blocking(&[
            ("graph.facebook.com", "block"),
            ("tracker.example", "block"),
        ]);
        shared.organisations = crate::organisations::Organisations::open(Box::new(
            crate::organisations::tests::sample(),
        ))
        .ok();
        shared.owners = crate::owners::Owners::bundled();
        let meta = IpAddr::from([157, 240, 1, 35]);
        let example = IpAddr::from([93, 184, 216, 34]);
        assert_eq!(
            shared.address_verdict(Some(APP), meta),
            None,
            "no answer tied it"
        );
        shared.learn(&dns_answer("graph.facebook.com", [157, 240, 1, 35]), None);
        shared.learn(&dns_answer("tracker.example", [93, 184, 216, 34]), None);
        assert!(shared.address_verdict(Some(APP), meta).is_some());
        assert_eq!(shared.address_verdict(Some(BROWSER), meta), None);
        assert_eq!(
            shared.address_verdict(Some(APP), example),
            None,
            "Example Net is no company's own"
        );
        // Another name given the address: never blocked by it again while that answer is held.
        shared.learn(&dns_answer("www.facebook.com", [157, 240, 1, 35]), None);
        assert_eq!(shared.address_verdict(Some(APP), meta), None);
        // An app's own resolver's answer ties nothing (it names only that app's flows).
        shared.learn(
            &dns_answer("graph.facebook.com", [157, 240, 2, 35]),
            Some(APP),
        );
        assert_eq!(
            shared.address_verdict(Some(APP), IpAddr::from([157, 240, 2, 35])),
            None
        );
    }

    /// A hello in two segments is held, nothing written, until its name is read; then refused or released whole. A
    /// plain request's host is read the same way; a start that is neither goes through at once; a hold that runs out
    /// releases what it held; and a flow named by a row is decided again at each later read.
    #[test]
    fn a_hello_in_two_parts_is_held_then_decided() {
        let (shared, _) = blocking(ROWS);
        set(&shared, |s| s.apps_allowed = vec![(OTHER, Duration::MAX)]);
        let hello = crate::tls::tests::hello("App-Measurement.com", 16 * 1024);
        let (first, second) = hello.split_at(hello.len() / 2);
        let Some(mut gate) = shared.gate(Some(APP)) else {
            unreachable!("a gate")
        };
        assert_eq!(gate.feed(&shared, first), Step::Hold);
        assert!(gate.until().is_some());
        assert!(matches!(gate.feed(&shared, second), Step::Block(_)));
        let Some(mut gate) = shared.gate(Some(OTHER)) else {
            unreachable!("a gate")
        };
        assert_eq!(gate.feed(&shared, first), Step::Hold);
        assert_eq!(gate.feed(&shared, second), Step::Release(hello.clone()));
        assert!(gate.entry().is_some());
        assert_eq!(gate.feed(&shared, b"more"), Step::Through);
        // The user blocks it again: the next byte refuses it.
        set(&shared, |s| s.apps_allowed.clear());
        assert!(matches!(gate.feed(&shared, b"more"), Step::Block(_)));
        let Some(mut gate) = shared.gate(Some(APP)) else {
            unreachable!("a gate")
        };
        assert_eq!(gate.feed(&shared, b"GET /a HTTP/1.1\r\nHo"), Step::Hold);
        assert!(matches!(
            gate.feed(&shared, b"st: app-measurement.com\r\n\r\n"),
            Step::Block(_)
        ));
        let Some(mut gate) = shared.gate(Some(APP)) else {
            unreachable!("a gate")
        };
        assert_eq!(gate.feed(&shared, b"SSH-2.0-OpenSSH\r\n"), Step::Through);
        let Some(mut gate) = shared.gate(Some(APP)) else {
            unreachable!("a gate")
        };
        assert_eq!(gate.feed(&shared, first), Step::Hold);
        assert_eq!(gate.ran_out(), first.to_vec());
        assert_eq!(gate.feed(&shared, second), Step::Through);
        let www = crate::tls::tests::hello("www.example.com", 16 * 1024);
        let Some(mut gate) = shared.gate(Some(APP)) else {
            unreachable!("a gate")
        };
        assert_eq!(gate.feed(&shared, &www), Step::Through);
        assert_eq!(gate.entry(), None);
        set(&shared, |s| s.on = false);
        assert!(
            shared.gate(Some(APP)).is_none(),
            "nothing is held while blocking is off"
        );
        assert!(shared.gate(None).is_none());
    }

    /// Another table's rows are other rows: what the old one counted goes.
    #[test]
    fn a_new_table_forgets_the_old_ones_tallies() {
        let (shared, _) = blocking(ROWS);
        assert!(
            shared
                .lookup_blocked(Some(APP), &query("app-measurement.com", 1))
                .is_some()
        );
        set(&shared, |s| s.covered.push(BROWSER));
        assert_eq!(
            shared.blocked_tallies().len(),
            1,
            "the same table keeps them"
        );
        set(&shared, |s| {
            s.table = Some(Arc::new(table(&[("other.example", "block")])));
        });
        assert_eq!(shared.blocked_tallies().len(), 0);
    }
}
