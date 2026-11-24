//! The live counters behind "Now" (ADR 0046, decision 2 (d)): each placed second's bytes, as the app sent
//! and received them, go to its app's counts by state, in whole minutes over the last hour and since
//! the screen last came on, and to the destination its flow reached, named as W3 names it. A chained
//! app's flow whose destination stays out of the log adds to its app's counts only, with the mark that it
//! went through the user's tool ("Log where these apps connect" off). Lookups to the network part's own DNS address
//! are the log's only.
//!
//! All of it is memory only, written to no file, kept with retention "none" too, handed to the next
//! engine when the tunnel is set up again, and gone when the network part stops. It is bounded: at most [`APPS`]
//! apps, each with at most 61 minutes of counts, and [`PLACES`] destinations for all apps together and
//! [`PLACES_PER_APP`] for one, each with at most 61 minutes of counts and names of at most 253 bytes;
//! past a bound, the app or destination with bytes the longest ago gives way (ADR 0046's "How it is
//! built" gives the bytes).
//!
//! The seconds not placed yet count in the snapshot in a column of their own, "not told yet", from the
//! flows' and the held segments' marks, so that the view needs no reading to show them.
//!
//! Bytes in no state are also counted by why (no usage access, no events, told too late, no app, not
//! told), in the minutes that hold some only, so that "Now" can say why an app's bytes have no state (W5's
//! third part). And a window of its own, "while the screen was off", holds each app's bytes by state from
//! the moment the screen went off to the moment it came on again, kept from then until the screen next
//! goes off, for the summary's "While the screen was off (2 h 10 min), N apps you were not using sent X"
//! (ADR 0046, decision 2 (a)). [`Counts::clear`] forgets all of it at once, for ADR 0047's profile.

use super::activity::{Mark, Of};
use super::logbook::without_destination;
use super::proxied::{holds_destination, own_first_hop};
use super::{Flow, NamedBy, Network, Shared, lock};
use crate::snapshot::{AppNow, COLUMNS, OFF, PlaceNow, Snapshot, WINDOWS as VIEW_WINDOWS, Ways};
use crate::states::Placed;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::Duration;

/// At most this many apps have counts kept; one more takes the place of the one with bytes the
/// longest ago.
pub(super) const APPS: usize = 512;

/// At most this many destinations are kept for all apps together.
pub(super) const PLACES: usize = 2_048;

/// At most this many destinations are kept for one app.
pub(super) const PLACES_PER_APP: usize = 128;

/// At most this many addresses' organisations are kept for the view; past it they are looked up anew.
const ORGANISATIONS: usize = 4_096;

/// At most this many addresses' organisations are looked up for one snapshot, out of every lock, so that
/// the first snapshot after a busy hour neither holds the engine nor waits long (review b1 of W5's
/// second part, engine, finding 7); the others come in the next.
const LOOKUPS_PER_VIEW: usize = 64;

/// The windows of the live view in whole minutes: the current one and the 9, or the 59, before it.
pub(super) const WINDOWS: [u64; 2] = [10, 60];

/// How long after an app's own proxy's connection ends "Now" still shows its first hop in full, while its app's
/// first hops are not kept (ADR 0052, R2): in time since the phone started, sleep included, so that ten minutes
/// asleep are ten minutes and a wall clock set back or forward changes nothing in it. Equal to
/// `proxied::SUBSTITUTION`, and apart from it: that one is how long a messenger's direct connection keeps a
/// connection elsewhere from being named its proxy.
pub(super) const SHOWN: Duration = Duration::from_mins(10);

/// An app's own proxy's connection that ended, for its first hop's window in "Now": its app, its first hop as a
/// place keys it, and when it ended, in time since the phone started.
struct End {
    uid: Option<u32>,
    flow: Flow,
    at: Duration,
}

/// Whether an end of the app `uid` whose window still runs at `boot` is the place `flow`'s. Saturating: an end
/// near the clock's largest value must not overflow, which aborts a release build.
fn shown_after(ended: &[End], uid: Option<u32>, flow: &Flow, boot: Duration) -> bool {
    ended.iter().any(|end| {
        end.uid == uid && end.at.saturating_add(SHOWN) > boot && same_place(&end.flow, flow)
    })
}

/// Bytes up and down by column: no state, in use, with its notification, in the background.
type ByState = [Ways; 4];

/// Bytes up and down in no state, by why ([`Placed::reason`]): no usage access, no events, told too
/// late, no app, not told.
type ByReason = [Ways; 5];

/// Counts in whole minutes: the minute (of the wall clock, since 1970), and its counts.
type Minutes<T> = VecDeque<(u64, T)>;

/// Adds to the count of `minute`, kept in order, and forgets the minutes no window reaches from the
/// newest.
fn add_minute<T: Default>(minutes: &mut Minutes<T>, minute: u64, add: impl FnOnce(&mut T)) {
    let at = minutes.iter().rposition(|(m, _)| *m <= minute);
    match at {
        Some(i) if minutes[i].0 == minute => add(&mut minutes[i].1),
        _ => {
            let mut counts = T::default();
            add(&mut counts);
            minutes.insert(at.map_or(0, |i| i + 1), (minute, counts));
        }
    }
    let newest = minutes.back().map_or(minute, |(m, _)| *m);
    while minutes
        .front()
        .is_some_and(|(m, _)| m + WINDOWS[1] <= newest)
    {
        minutes.pop_front();
    }
}

/// How a placed second's bytes were seen: on a flow to a destination, directly or through the user's
/// tool; on a chained flow whose destination stays out of the log; on a flow that went directly and
/// whose destination a chain set after it opened leaves out; or as lookups, which the live view does
/// not count.
#[derive(Clone, Copy)]
pub(super) enum Seen<'a> {
    Flow(&'a Flow),
    Routed(&'a Flow),
    Hidden,
    /// A flow not through the tool whose destination stays out: through a `WireGuard` tunnel (W7) with
    /// "Log where these apps connect" off, with its number, or one that went directly before a chain left
    /// its destination out.
    HiddenDirect(Option<u32>),
    Lookups,
}

impl<'a> Seen<'a> {
    pub(super) fn of(of: &'a Of) -> Self {
        match of {
            Of::Flow {
                flow,
                hidden,
                direct,
            } => Self::live(flow, *hidden, *direct),
            Of::Lookups => Self::Lookups,
        }
    }

    /// A live flow, by whether its destination stays out of the log and whether it went directly: only
    /// a flow that went through the tool marks its app so (review b2 of W5's second part, N3).
    pub(super) fn live(flow: &'a Flow, hidden: bool, direct: bool) -> Self {
        match (hidden, direct) {
            // An app's own proxy with its destination left out keeps a place of its own: its kind, with no
            // address or name (ADR 0052).
            (true, true) if flow.proxy.is_some() => Self::Flow(flow),
            (true, false) => Self::Hidden,
            (true, true) => Self::HiddenDirect(match flow.via {
                crate::engine::Via::Tunnel(t) => Some(t),
                crate::engine::Via::Direct | crate::engine::Via::Tool => None,
            }),
            (false, true) => Self::Flow(flow),
            (false, false) => Self::Routed(flow),
        }
    }
}

/// A destination an app reached: the latest flow to it, as it was named, and its bytes.
struct Place {
    flow: Flow,
    minutes: Minutes<Ways>,
    session: Ways,
    /// The last second with bytes to it.
    last: u64,
    /// The last second a flow to it that went through the user's tool counted, if one did.
    routed: Option<u64>,
}

/// Whether two flows reach one destination as the live view shows it: by name, where the name came
/// from, the DNS name beside it and the app's own DNS; and by address where neither has a name; and
/// through the same proxy, if any (ADR 0052).
pub(super) fn same_place(a: &Flow, b: &Flow) -> bool {
    a.proxy == b.proxy
        && a.name == b.name
        && a.named_by == b.named_by
        && a.dns_name == b.dns_name
        && a.dns == b.dns
        && (a.name.is_some() || a.destination.ip() == b.destination.ip())
}

/// One app's counts.
#[derive(Default)]
struct App {
    /// Each minute's bytes by state, and in no state by why where it holds some: one entry, so that a minute
    /// leaves with both (review c1 of W5's third part, engine, finding 3: kept apart, the whys outlived their
    /// minute, and after a clock set back exceeded the column of no state, which the reader refuses).
    minutes: Minutes<Columns>,
    session: ByState,
    session_reasons: ByReason,
    /// The last second a flow of it went through the user's tool with its destination left out.
    through_tool: Option<u64>,
    /// The last second a flow of it went through a `WireGuard` tunnel with its destination left out, and
    /// that tunnel's number (W7).
    through_tunnel: Option<(u64, u32)>,
    /// The last second it sent or received.
    last: u64,
    places: Vec<Place>,
}

/// One minute of an app: its bytes by state, and those in no state by why, only where it holds some.
#[derive(Default)]
struct Columns {
    states: ByState,
    reasons: Option<Box<ByReason>>,
}

/// One app's bytes in the window "while the screen was off".
#[derive(Default)]
struct OffApp {
    bytes: ByState,
    reasons: ByReason,
    /// The last second it sent or received.
    last: u64,
}

/// The window "while the screen was off": from the moment the screen went off to the moment it came on
/// again, in milliseconds since 1970, and each app's bytes by state in it, at most [`APPS`] apps. A second
/// counts in it when it began in that span. Kept from the screen-on that closed it until the screen next
/// goes off; while the screen is off, the window runs.
pub(super) struct Off {
    pub(super) from: u64,
    pub(super) until: Option<u64>,
    apps: HashMap<Option<u32>, OffApp>,
}

impl Off {
    /// Whether the second `second` falls in the window.
    fn holds(&self, second: u64) -> bool {
        let at = second.saturating_mul(1000);
        at >= self.from && self.until.is_none_or(|until| at < until)
    }

    fn count(&mut self, uid: Option<u32>, second: u64, placed: Placed, ways: Ways) {
        if !self.apps.contains_key(&uid) && self.apps.len() >= APPS {
            let oldest = self
                .apps
                .iter()
                .min_by_key(|(_, app)| app.last)
                .map(|(uid, _)| *uid);
            if let Some(oldest) = oldest {
                self.apps.remove(&oldest);
            }
        }
        let app = self.apps.entry(uid).or_default();
        add(&mut app.bytes[placed.column()], ways);
        if let Some(why) = placed.reason() {
            add(&mut app.reasons[why], ways);
        }
        app.last = app.last.max(second);
    }
}

impl App {
    /// Adds a placed second's bytes, in `minute`, to its column, and to its why where it has no state.
    fn add(&mut self, minute: u64, placed: Placed, ways: Ways, in_session: bool) {
        let column = placed.column();
        add_minute(&mut self.minutes, minute, |counts: &mut Columns| {
            add(&mut counts.states[column], ways);
            if let Some(why) = placed.reason() {
                add(
                    &mut counts.reasons.get_or_insert_with(Box::default)[why],
                    ways,
                );
            }
        });
        if in_session {
            add(&mut self.session[column], ways);
            if let Some(why) = placed.reason() {
                add(&mut self.session_reasons[why], ways);
            }
        }
    }
}

/// Each app's counts by state, and the window since the screen came on.
#[derive(Default)]
pub(super) struct Counts {
    apps: HashMap<Option<u32>, App>,
    /// How many destinations all apps keep together.
    places: usize,
    /// The organisation behind each address the view looked up, at most [`ORGANISATIONS`] of them.
    organisations: HashMap<std::net::IpAddr, Option<(Network, String)>>,
    /// When the screen last came on, in milliseconds since 1970: the window "since the screen came on".
    session: Option<u64>,
    /// The window "while the screen was off", once the screen went off.
    off: Option<Off>,
    /// The first second counted since the live memory was last cleared ([`Counts::clear`]), 0 for never:
    /// seconds before it, placed later, are not counted again.
    cleared: u64,
    /// A moment at or before which no screen-off opens a window: that of a window the last clear forgot, or
    /// the new clock's now when a clock set back forgot one, so that a reading that tells it again, as the network
    /// part's Kotlin side does with its moments moved back, does not open it anew, empty (review c1 of W5's third
    /// part, engine, finding 2).
    off_floor: u64,
    /// When the engine began counting, in milliseconds since 1970 (0 before it is told): the window while the
    /// screen was off begins no earlier, so that it never claims hours the network part did not see (finding 6).
    began: u64,
    /// The ends of apps' own proxies' connections, for their first hops' window ([`SHOWN`]): one for each place, the
    /// latest, at most [`PLACES_PER_APP`] of one app's and [`PLACES`] in all. Cleared with the rest, and handed to
    /// the next engine with the rest.
    ended: Vec<End>,
}

impl Counts {
    /// The screen came on at `since`: the window since it did begins anew, and the window "while the screen
    /// was off", if it runs and began before, ends there.
    pub(super) fn screen_on(&mut self, since: u64) {
        if let Some(off) = self
            .off
            .as_mut()
            .filter(|off| off.until.is_none() && off.from <= since)
        {
            off.until = Some(since);
        }
        if self.session == Some(since) {
            return;
        }
        self.session = Some(since);
        for app in self.apps.values_mut() {
            app.session = ByState::default();
            app.session_reasons = ByReason::default();
            for place in &mut app.places {
                place.session = Ways::default();
            }
        }
    }

    /// The screen went off at `at`: the window "while the screen was off" begins there, or where the engine
    /// began counting if that is later, in place of the one before, unless it is that one, or one before it,
    /// or one the last clear or a clock set back forgot.
    pub(super) fn screen_off(&mut self, at: u64) {
        let from = at.max(self.began);
        if at <= self.off_floor || self.off.as_ref().is_some_and(|off| off.from >= from) {
            return;
        }
        self.off = Some(Off {
            from,
            until: None,
            apps: HashMap::new(),
        });
    }

    /// The engine began counting at `now`, in milliseconds since 1970: kept from the first engine of the run,
    /// as the counts are handed over.
    pub(super) fn begin(&mut self, now: u64) {
        if self.began == 0 {
            self.began = now;
        }
    }

    /// Forgets everything the live view holds, at the wall clock's `now`: every app's counts in every
    /// window, its destinations, the window "while the screen was off" and the organisations looked up, for
    /// ADR 0047's profile, which clears them at each screen-off. Seconds before `now` that are placed later
    /// are not counted, so nothing from before shows again; the moment the screen came on is kept, as it
    /// names no app. What this cannot clear is not the live view's: the flows still open, which the engine
    /// needs to carry them, and the seconds and segments waiting for their states, which are the log's.
    pub(super) fn clear(&mut self, now: u64) {
        let off_floor = self.off.as_ref().map_or(self.off_floor, |off| off.from);
        *self = Self {
            session: self.session,
            cleared: now.div_ceil(1000),
            off_floor: off_floor.max(self.off_floor),
            began: now,
            ..Self::default()
        };
    }

    /// Whether the live view counts the second `second`: one before the last clear is not.
    pub(super) fn counted(&self, second: u64) -> bool {
        second >= self.cleared
    }

    /// The wall clock was set back to `now`: the minutes later than its own are of the old clock, and so
    /// is the moment the screen came on if it is later too; both are forgotten, so that the windows hold
    /// the new clock's bytes (review b1 of W5's second part, engine, finding 5). The moments of a clear, and
    /// when counting began, come down to the new clock's now, so that what is counted after shows (review c1
    /// of W5's third part, engine, finding 1: a clear before a set back blanked the view for the set back's
    /// length).
    pub(super) fn set_back(&mut self, now: u64) {
        self.cleared = self.cleared.min(now.div_ceil(1000));
        self.off_floor = self.off_floor.min(now);
        self.began = self.began.min(now);
        let minute = now / 60_000;
        let mut gone = 0;
        for app in self.apps.values_mut() {
            app.minutes.retain(|(m, _)| *m <= minute);
            for place in &mut app.places {
                place.minutes.retain(|(m, _)| *m <= minute);
            }
            app.places.retain(|place| {
                let keep = !place.minutes.is_empty() || place.session != Ways::default();
                gone += usize::from(!keep);
                keep
            });
        }
        self.places -= gone;
        // The window "while the screen was off" of the old clock, if it reaches past the new clock's now.
        if self
            .off
            .as_ref()
            .is_some_and(|off| off.until.unwrap_or(off.from) > now)
        {
            self.off = None;
            // The network part's Kotlin side moves the window's moments back with the clock and tells them again: the
            // window, forgotten with its bytes, is not opened anew from them, empty.
            self.off_floor = now;
        }
        if self.session.is_some_and(|since| since > now) {
            self.session = None;
            for app in self.apps.values_mut() {
                app.session = ByState::default();
                app.session_reasons = ByReason::default();
                for place in &mut app.places {
                    place.session = Ways::default();
                }
            }
        }
    }

    /// Counts the place a flow was counted under, `from`, as the place `to` from now on: as a proxy its bytes
    /// declared, or a messenger's inferred, names it (ADR 0052), or a messenger's proxy taken back makes it what
    /// it would have been (the fix round's S-M2). Its bytes stay, merged into a place that already is `to`, and
    /// what was said of it goes.
    pub(super) fn rename_place(&mut self, uid: Option<u32>, from: &Flow, to: &Flow) {
        let Some(app) = self.apps.get_mut(&uid) else {
            return;
        };
        let mut at = 0;
        while at < app.places.len() {
            let flow = &app.places[at].flow;
            if same_place(flow, from) && !same_place(flow, to) && rename(&mut app.places, at, to) {
                // Merged: the place now at `at` is another, read next.
                self.places -= 1;
            } else {
                at += 1;
            }
        }
    }

    /// An app's own proxy's connection ended at `at`, in time since the phone started, its first hop `flow`: its
    /// place stays in full for [`SHOWN`] more. A later end of the same place takes the earlier's place. Past an app's
    /// bound its own oldest end goes, and past the bound of all the oldest of the app that holds the most. An end
    /// read as `Duration::MAX`, the clock's failure, is not kept: its place is stripped once its flow is gone.
    pub(super) fn end(&mut self, uid: Option<u32>, flow: Flow, at: Duration) {
        if at == Duration::MAX {
            return;
        }
        if let Some(end) = self
            .ended
            .iter_mut()
            .find(|end| end.uid == uid && same_place(&end.flow, &flow))
        {
            end.at = end.at.max(at);
            return;
        }
        self.ended.push(End { uid, flow, at });
        let over = if self.ended.iter().filter(|end| end.uid == uid).count() > PLACES_PER_APP {
            Some(uid)
        } else if self.ended.len() > PLACES {
            let mut by_app: HashMap<Option<u32>, usize> = HashMap::new();
            for end in &self.ended {
                *by_app.entry(end.uid).or_default() += 1;
            }
            by_app
                .into_iter()
                .max_by_key(|(_, n)| *n)
                .map(|(uid, _)| uid)
        } else {
            None
        };
        if let Some(over) = over
            && let Some(oldest) = (0..self.ended.len())
                .filter(|&i| self.ended[i].uid == over)
                .min_by_key(|&i| self.ended[i].at)
        {
            self.ended.swap_remove(oldest);
        }
    }

    /// The flows of the app `uid`'s places, read with no view, which sweeps.
    #[cfg(test)]
    pub(super) fn places_of(&self, uid: Option<u32>) -> Vec<Flow> {
        self.apps
            .get(&uid)
            .map(|app| app.places.iter().map(|p| p.flow.clone()).collect())
            .unwrap_or_default()
    }

    /// Whether an end of the app `uid` whose window still runs at `boot` is the place `flow`'s.
    pub(super) fn shown_after_end(&self, uid: Option<u32>, flow: &Flow, boot: Duration) -> bool {
        shown_after(&self.ended, uid, flow, boot)
    }

    /// Strips the first hops whose window ended at `boot`, in time since the phone started (R2): of each app whose
    /// first hops `keeps` does not keep, every place that shows an own proxy's first hop, that no end whose window
    /// still runs matches, and that `open` says no live flow of its app matches. Each is left out as the log leaves
    /// it, merged into the app's place of the same kind and facts, if it has one, and its address's organisation
    /// leaves the view's memory (as `hide` does for chained apps). A stripped place is never full again. Then the
    /// ends past their window go. The ends are read first, as they are fewer than the live flows.
    pub(super) fn expire_first_hops(
        &mut self,
        boot: Duration,
        keeps: &dyn Fn(Option<u32>) -> bool,
        open: &dyn Fn(Option<u32>, &Flow) -> bool,
    ) {
        let Self {
            apps,
            places,
            organisations,
            ended,
            ..
        } = self;
        for (&uid, app) in apps.iter_mut() {
            if keeps(uid) {
                continue;
            }
            let mut at = 0;
            while at < app.places.len() {
                let flow = &app.places[at].flow;
                if !own_first_hop(flow) || shown_after(ended, uid, flow, boot) || open(uid, flow) {
                    at += 1;
                    continue;
                }
                organisations.remove(&flow.destination.ip());
                let stripped = without_destination(flow);
                if rename(&mut app.places, at, &stripped) {
                    *places -= 1;
                } else {
                    at += 1;
                }
            }
        }
        ended.retain(|end| end.at.saturating_add(SHOWN) > boot);
    }

    /// Sets every place of the apps `of` names that holds where an app asked its proxy to go back to its first hop,
    /// `to_first_hop` (`Shared::first_hop`), as "Log where these apps connect" turned off asks (R6): a place that
    /// comes to be one already there is merged into it, and a plain request's keeps its own address and names. The
    /// first hops then stay for their window.
    pub(super) fn first_hops(
        &mut self,
        of: &dyn Fn(Option<u32>) -> bool,
        to_first_hop: &dyn Fn(&Flow) -> Flow,
    ) {
        for (&uid, app) in &mut self.apps {
            if !of(uid) {
                continue;
            }
            let mut at = 0;
            while at < app.places.len() {
                if holds_destination(&app.places[at].flow) {
                    let first_hop = to_first_hop(&app.places[at].flow);
                    if rename(&mut app.places, at, &first_hop) {
                        self.places -= 1;
                        continue;
                    }
                }
                at += 1;
            }
        }
    }

    /// Leaves out the destinations of the apps that `hidden` names, keeping their bytes, marked as through
    /// the tool from the last second with bytes to a destination reached through it; and forgets the
    /// organisations looked up, which name destinations too (review b2 of W5's second part, N8).
    pub(super) fn hide(&mut self, hidden: impl Fn(Option<u32>) -> bool) {
        for (uid, app) in &mut self.apps {
            if !app.places.is_empty() && hidden(*uid) {
                let routed = app.places.iter().filter_map(|p| p.routed).max();
                let tunnelled = app
                    .places
                    .iter()
                    .filter_map(|p| match p.flow.via {
                        crate::engine::Via::Tunnel(t) => Some((p.last, t)),
                        _ => None,
                    })
                    .max();
                self.places -= app.places.len();
                app.places.clear();
                if let Some(last) = routed {
                    app.through_tool = Some(app.through_tool.map_or(last, |s| s.max(last)));
                }
                if let Some(seen) = tunnelled {
                    app.through_tunnel = app.through_tunnel.max(Some(seen));
                }
            }
        }
        self.organisations.clear();
    }

    /// Counts one placed second of the app `uid`, `bytes` its counts (as the app sent and received
    /// them, then the tunnel's), for the live view.
    pub(super) fn count(
        &mut self,
        uid: Option<u32>,
        second: u64,
        bytes: [u64; 4],
        placed: Placed,
        seen: Seen<'_>,
    ) {
        let (up, down) = (bytes[0], bytes[1]);
        if (up == 0 && down == 0) || matches!(seen, Seen::Lookups) || !self.counted(second) {
            return;
        }
        if let Some(off) = self.off.as_mut().filter(|off| off.holds(second)) {
            off.count(uid, second, placed, [up, down]);
        }
        if !self.apps.contains_key(&uid) && self.apps.len() >= APPS {
            let oldest = self
                .apps
                .iter()
                .min_by_key(|(_, app)| app.last)
                .map(|(uid, _)| *uid);
            if let Some(gone) = oldest.and_then(|uid| self.apps.remove(&uid)) {
                self.places -= gone.places.len();
            }
        }
        let in_session = self
            .session
            .is_some_and(|since| second.saturating_mul(1000) >= since);
        let minute = second / 60;
        let app = self.apps.entry(uid).or_default();
        app.add(minute, placed, [up, down], in_session);
        app.last = app.last.max(second);
        let (flow, routed) = match seen {
            Seen::Flow(flow) => (flow, false),
            Seen::Routed(flow) => (flow, true),
            Seen::Hidden => {
                app.through_tool = Some(app.through_tool.map_or(second, |s| s.max(second)));
                return;
            }
            Seen::HiddenDirect(Some(t)) => {
                app.through_tunnel = app.through_tunnel.max(Some((second, t)));
                return;
            }
            Seen::HiddenDirect(None) | Seen::Lookups => return,
        };
        let known = app
            .places
            .iter()
            .position(|place| same_place(&place.flow, flow));
        let at = if let Some(at) = known {
            at
        } else {
            {
                if app.places.len() >= PLACES_PER_APP {
                    if let Some(oldest) = oldest_place(&app.places) {
                        app.places.swap_remove(oldest);
                        self.places -= 1;
                    }
                } else if self.places >= PLACES {
                    self.forget_oldest_place();
                }
                let Some(app) = self.apps.get_mut(&uid) else {
                    return;
                };
                app.places.push(Place {
                    flow: flow.clone(),
                    minutes: VecDeque::new(),
                    session: Ways::default(),
                    last: second,
                    routed: None,
                });
                self.places += 1;
                app.places.len() - 1
            }
        };
        let Some(place) = self
            .apps
            .get_mut(&uid)
            .and_then(|app| app.places.get_mut(at))
        else {
            return;
        };
        // Any flow through the tool marks it, not only the first (review b3 of W5's second part, R6).
        if routed {
            place.routed = Some(place.routed.map_or(second, |s| s.max(second)));
        }
        // The latest flow's address, ECH, resolver and network, for a destination named alike.
        place.flow.destination = flow.destination;
        place.flow.protocol = flow.protocol;
        place.flow.ech = flow.ech;
        place.flow.came_in = flow.came_in;
        place.flow.network = flow.network;
        if place.flow.resolver != flow.resolver {
            place.flow.resolver.clone_from(&flow.resolver);
        }
        add_minute(&mut place.minutes, minute, |counts: &mut Ways| {
            counts[0] += up;
            counts[1] += down;
        });
        if in_session {
            place.session[0] += up;
            place.session[1] += down;
        }
        place.last = place.last.max(second);
    }

    /// Forgets the destination, of any app, that gives way first ([`oldest_place`]).
    fn forget_oldest_place(&mut self) {
        let oldest = self
            .apps
            .iter()
            .filter_map(|(uid, app)| {
                oldest_place(&app.places).map(|at| {
                    let place = &app.places[at];
                    ((own_first_hop(&place.flow), place.last), *uid, at)
                })
            })
            .min();
        if let Some((_, uid, at)) = oldest
            && let Some(app) = self.apps.get_mut(&uid)
        {
            app.places.swap_remove(at);
            self.places -= 1;
        }
    }

    /// Forgets what no window reaches any more at `now`, in milliseconds since 1970: minutes past the
    /// longest window, and apps and destinations with no bytes left in it nor since the screen came on.
    fn forget_old(&mut self, now: u64) {
        let first = (now / 60_000).saturating_sub(WINDOWS[1] - 1);
        let mut gone = 0;
        self.apps.retain(|_, app| {
            app.minutes.retain(|(minute, _)| *minute >= first);
            app.places.retain_mut(|place| {
                place.minutes.retain(|(minute, _)| *minute >= first);
                let keep = !place.minutes.is_empty() || place.session != Ways::default();
                gone += usize::from(!keep);
                keep
            });
            let keep = !app.minutes.is_empty() || app.session != ByState::default();
            if !keep {
                gone += app.places.len();
            }
            keep
        });
        self.places -= gone;
    }
}

/// Where the destination that gives way first is in `places`: of those that show no own proxy's first hop, the one
/// with bytes the longest ago, and a first hop only when every place is one (R8). So no flood of other
/// destinations pushes an app's own proxy out of "Now" before its window ends.
fn oldest_place(places: &[Place]) -> Option<usize> {
    places
        .iter()
        .enumerate()
        .min_by_key(|(_, place)| (own_first_hop(&place.flow), place.last))
        .map(|(at, _)| at)
}

/// Gives the place at `at` the identity of `to`, merged into the place that already has it, if one does: whether
/// it was merged, and so is gone.
fn rename(places: &mut Vec<Place>, at: usize, to: &Flow) -> bool {
    let Some(into) = (0..places.len()).find(|&i| i != at && same_place(&places[i].flow, to)) else {
        places[at].flow = to.clone();
        return false;
    };
    let from = places.swap_remove(at);
    // The last place moved into `at`.
    let into = if into == places.len() { at } else { into };
    merge(&mut places[into], from);
    true
}

/// Adds `from`'s bytes to `into`'s, in every window, and its latest seconds.
fn merge(into: &mut Place, from: Place) {
    for (minute, ways) in from.minutes {
        add_minute(&mut into.minutes, minute, |counts: &mut Ways| {
            add(counts, ways);
        });
    }
    add(&mut into.session, from.session);
    into.last = into.last.max(from.last);
    into.routed = into.routed.max(from.routed);
}

impl Shared {
    /// What the live view "Now" draws at the wall clock's `now`: each app's bytes by state in each
    /// window, the seconds not placed yet in a column apart, and its destinations with theirs.
    pub(super) fn now_view(&self, now: u64) -> Snapshot {
        let boot = self.clock.since_boot();
        let tool = self.chain().map(|chain| chain.tool);
        // The tool whose own servers the view leaves out: "Log where these apps connect" is off.
        let hidden_tool = self
            .chain()
            .filter(|chain| !chain.log_destinations)
            .map(|chain| chain.tool);
        let (view, head, mut found) = {
            let mut live = lock(&self.live);
            let mut activity = lock(&self.activity);
            activity.counts.forget_old(now);
            // A first hop whose window ended is not drawn (R2). The switch is read under `live`, as naming reads it.
            let keeps = self.keeps_first_hops();
            self.sweep(&mut live, &mut activity, boot, &keeps);
            let counts = &activity.counts;
            let off = counts.off.as_ref().map(|off| (off.from, off.until));
            let mut view = View::new(now, counts.session, off, counts.cleared);
            for (&uid, app) in &counts.apps {
                view.settled(uid, app);
            }
            if let Some(off) = &counts.off {
                for (&uid, app) in &off.apps {
                    view.settled_off(uid, app);
                }
            }
            // The seconds not placed yet: in the live flows and the segments held.
            for live in live.values() {
                let marks = lock(&live.bytes.marks);
                let seen = Seen::live(&live.flow, live.hidden, live.direct);
                view.waiting(live.flow.uid, &marks, live.bytes.now(), seen);
            }
            for piece in &activity.held {
                view.waiting(piece.uid, &piece.marks, piece.last, Seen::of(&piece.of));
            }
            let head = (
                activity.known(),
                activity.told_until(),
                activity.screen(),
                activity.counts.session,
                view.apps
                    .keys()
                    .map(|&uid| (uid, activity.now(uid)))
                    .collect::<HashMap<_, _>>(),
            );
            // The organisations already known; the others to look up, out of the locks.
            let mut found = HashMap::new();
            for app in view.apps.values() {
                for (flow, _) in &app.places {
                    let address = flow.destination.ip();
                    if flow.named_by != NamedBy::Organisation
                        && let Some(known) = activity.counts.organisations.get(&address)
                    {
                        found.insert(address, known.clone());
                    }
                }
            }
            (view, head, found)
        };
        self.prune_inferred(boot);
        self.look_up(&view, &mut found);
        let (known, told_until, screen, session, states) = head;
        let off = view.off;
        let apps = view
            .apps
            .into_iter()
            .map(|(uid, app)| {
                let places = app
                    .places
                    .into_iter()
                    .map(|(flow, bytes)| {
                        let organisation = if flow.named_by == NamedBy::Organisation {
                            self.organisation_of(&flow)
                        } else {
                            found.get(&flow.destination.ip()).cloned().flatten()
                        };
                        PlaceNow {
                            flow,
                            organisation,
                            bytes,
                        }
                    })
                    .collect();
                AppNow {
                    uid,
                    now: states.get(&uid).copied().flatten(),
                    tool: uid.is_some() && uid == tool,
                    through_tool: app.through_tool,
                    through_tunnel: app.through_tunnel,
                    servers_hidden: uid.is_some() && uid == hidden_tool,
                    bytes: app.bytes,
                    places,
                }
            })
            .collect();
        Snapshot {
            taken: now,
            known,
            told_until,
            screen,
            session,
            off,
            apps,
        }
    }

    /// Looks up, with no lock held, the organisations of at most [`LOOKUPS_PER_VIEW`] of the view's
    /// destinations not `found` yet, keeps them for the next snapshots and adds them to `found`.
    fn look_up(
        &self,
        view: &View,
        found: &mut HashMap<std::net::IpAddr, Option<(Network, String)>>,
    ) {
        let wanted: Vec<_> = view
            .apps
            .values()
            .flat_map(|app| app.places.iter())
            .filter(|(flow, _)| flow.named_by != NamedBy::Organisation)
            .map(|(flow, _)| flow.destination.ip())
            .filter(|address| !found.contains_key(address))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .take(LOOKUPS_PER_VIEW)
            .collect();
        if wanted.is_empty() {
            return;
        }
        let looked: Vec<_> = wanted
            .into_iter()
            .map(|address| (address, self.organisation(address)))
            .collect();
        {
            let mut activity = lock(&self.activity);
            let kept = &mut activity.counts.organisations;
            if kept.len() + looked.len() > ORGANISATIONS {
                kept.clear();
            }
            kept.extend(looked.iter().cloned());
        }
        found.extend(looked);
    }

    /// The network and organisation behind a destination: the flow's own where the organisation table
    /// named it, else the table's for its address, if the network part has the table.
    fn organisation_of(&self, flow: &Flow) -> Option<(Network, String)> {
        if flow.named_by == NamedBy::Organisation
            && let (Some(network), Some(name)) = (flow.network, &flow.name)
        {
            return Some((network, name.clone()));
        }
        self.organisation(flow.destination.ip())
    }
}

/// The live view as it is built: each app's bytes by window and column, and its destinations'.
struct View {
    /// The first minute of each window of whole minutes.
    firsts: [u64; 2],
    session: Option<u64>,
    /// The window "while the screen was off": when the screen went off, and came on again if it did.
    off: Option<(u64, Option<u64>)>,
    /// The first second counted since the live memory was last cleared.
    cleared: u64,
    apps: BTreeMap<Option<u32>, AppView>,
}

/// The column of the seconds not told yet.
const NOT_YET: usize = 4;

/// The first column of the bytes in no state by why.
const REASONS: usize = 5;

#[derive(Default)]
struct AppView {
    /// By window (10 minutes, an hour, since the screen came on, while the screen was off), then by column
    /// ([`crate::snapshot`]: no state, in use, with its notification, in the background, not told yet,
    /// then the no state's bytes by why).
    bytes: [[Ways; COLUMNS]; VIEW_WINDOWS],
    through_tool: bool,
    /// The tunnel it went through with its destinations left out, in a window (W7).
    through_tunnel: Option<u32>,
    places: Vec<(Flow, [Ways; 3])>,
    /// How many of them show an own proxy's first hop: they have a cap of their own (audit-A 9).
    first_hops: usize,
}

impl View {
    fn new(now: u64, session: Option<u64>, off: Option<(u64, Option<u64>)>, cleared: u64) -> Self {
        let minute = now / 60_000;
        Self {
            firsts: WINDOWS.map(|w| minute.saturating_sub(w - 1)),
            session,
            off,
            cleared,
            apps: BTreeMap::new(),
        }
    }

    /// The windows a second falls in: the 10 minutes, the hour, since the screen came on, while the screen
    /// was off.
    fn windows(&self, second: u64) -> [bool; VIEW_WINDOWS] {
        let minute = second / 60;
        let at = second.saturating_mul(1000);
        [
            minute >= self.firsts[0],
            minute >= self.firsts[1],
            self.session.is_some_and(|since| at >= since),
            self.off
                .is_some_and(|(from, until)| at >= from && until.is_none_or(|until| at < until)),
        ]
    }

    /// An app's counts placed.
    fn settled(&mut self, uid: Option<u32>, app: &App) {
        let mut view = AppView {
            through_tool: app
                .through_tool
                .is_some_and(|second| self.windows(second).iter().any(|&w| w)),
            through_tunnel: app
                .through_tunnel
                .filter(|(second, _)| self.windows(*second).iter().any(|&w| w))
                .map(|(_, t)| t),
            ..AppView::default()
        };
        for (minute, counts) in &app.minutes {
            let windows = self.windows(minute * 60);
            for (w, inside) in windows.into_iter().take(2).enumerate() {
                if inside {
                    add_columns(&mut view.bytes[w], &counts.states);
                    if let Some(reasons) = &counts.reasons {
                        add_reasons(&mut view.bytes[w], reasons);
                    }
                }
            }
        }
        add_columns(&mut view.bytes[2], &app.session);
        add_reasons(&mut view.bytes[2], &app.session_reasons);
        for place in &app.places {
            let mut bytes = [Ways::default(); 3];
            for (minute, counts) in &place.minutes {
                let windows = self.windows(minute * 60);
                for (w, inside) in windows.into_iter().take(2).enumerate() {
                    if inside {
                        add(&mut bytes[w], *counts);
                    }
                }
            }
            add(&mut bytes[2], place.session);
            if bytes != [Ways::default(); 3] {
                view.first_hops += usize::from(own_first_hop(&place.flow));
                view.places.push((place.flow.clone(), bytes));
            }
        }
        if view.bytes != [[Ways::default(); COLUMNS]; VIEW_WINDOWS]
            || view.through_tool
            || view.through_tunnel.is_some()
        {
            self.apps.insert(uid, view);
        }
    }

    /// An app's bytes in the window "while the screen was off".
    fn settled_off(&mut self, uid: Option<u32>, app: &OffApp) {
        let view = self.apps.entry(uid).or_default();
        add_columns(&mut view.bytes[OFF], &app.bytes);
        add_reasons(&mut view.bytes[OFF], &app.reasons);
    }

    /// The seconds not placed yet of one flow or segment, in its marks, `now` its counts after the
    /// last.
    fn waiting(&mut self, uid: Option<u32>, marks: &VecDeque<Mark>, now: [u64; 4], seen: Seen<'_>) {
        if matches!(seen, Seen::Lookups) {
            return;
        }
        let mut place: Option<Option<usize>> = None;
        for (i, mark) in marks.iter().enumerate() {
            let next = marks.get(i + 1).map_or(now, |m| m.counts);
            let ways = [
                next[0].saturating_sub(mark.counts[0]),
                next[1].saturating_sub(mark.counts[1]),
            ];
            // A second before the last clear stays out of the view, though the log may still get it.
            if ways == Ways::default() || mark.second < self.cleared {
                continue;
            }
            let windows = self.windows(mark.second);
            let app = self.apps.entry(uid).or_default();
            for (w, inside) in windows.into_iter().enumerate() {
                if inside {
                    add(&mut app.bytes[w][NOT_YET], ways);
                }
            }
            let flow = match seen {
                Seen::Hidden => {
                    app.through_tool = true;
                    continue;
                }
                Seen::Flow(flow) | Seen::Routed(flow) => flow,
                Seen::HiddenDirect(Some(t)) => {
                    app.through_tunnel = Some(t);
                    continue;
                }
                Seen::HiddenDirect(None) | Seen::Lookups => continue,
            };
            // The flow's destination, found once for all its marks (review b1, engine, nit 3). Own proxies' first
            // hops, and other places, each have [`PLACES_PER_APP`]: a flood of either never pushes out the other.
            let at = *place.get_or_insert_with(|| {
                app.places
                    .iter()
                    .position(|(f, _)| same_place(f, flow))
                    .or_else(|| {
                        let first_hop = own_first_hop(flow);
                        let held = if first_hop {
                            app.first_hops
                        } else {
                            app.places.len() - app.first_hops
                        };
                        (held < PLACES_PER_APP).then(|| {
                            app.first_hops += usize::from(first_hop);
                            app.places.push((flow.clone(), [Ways::default(); 3]));
                            app.places.len() - 1
                        })
                    })
            });
            let Some(at) = at else {
                continue;
            };
            for (w, inside) in windows.into_iter().take(3).enumerate() {
                if inside {
                    add(&mut app.places[at].1[w], ways);
                }
            }
        }
    }
}

fn add(to: &mut Ways, more: Ways) {
    to[0] += more[0];
    to[1] += more[1];
}

fn add_columns(to: &mut [Ways; COLUMNS], more: &ByState) {
    for (column, ways) in more.iter().enumerate() {
        add(&mut to[column], *ways);
    }
}

fn add_reasons(to: &mut [Ways; COLUMNS], more: &ByReason) {
    for (why, ways) in more.iter().enumerate() {
        add(&mut to[REASONS + why], *ways);
    }
}

#[cfg(test)]
mod tests {
    use super::super::activity::tests::{
        BACKGROUND, IN_USE, NOT_TOLD, NOTIFICATION, T, Telling, UID, flow, open, taken, telling_at,
        told, up_at,
    };
    use super::super::clock::Clock;
    use super::super::tests::shared_with;
    use super::*;
    use crate::states::{Interval, Known, State, Told};
    use std::net::SocketAddr;
    use std::sync::Arc;

    const MINUTE: u64 = 60_000;

    /// The bytes of `uid` in `snapshot`, by window and column.
    fn bytes_of(snapshot: &Snapshot, uid: Option<u32>) -> [[Ways; COLUMNS]; VIEW_WINDOWS] {
        snapshot
            .apps
            .iter()
            .find(|app| app.uid == uid)
            .map_or([[[0; 2]; COLUMNS]; VIEW_WINDOWS], |app| app.bytes)
    }

    fn app_of(snapshot: &Snapshot, uid: Option<u32>) -> Option<&AppNow> {
        snapshot.apps.iter().find(|app| app.uid == uid)
    }

    /// An app's bytes, placed by state, count in each window that reaches the minute they were counted
    /// in: the 10 minutes reach back at least 9 and at most 10 whole minutes, the hour 59 and 60; the
    /// seconds not told yet count apart; and "since the screen came on" from the second it came on.
    #[test]
    fn an_apps_bytes_count_by_state_in_each_window() {
        // T is 22:10; the screen came on at 22:12:30.
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 0, 100);
        up_at(&shared, &clock, &bytes, 2 * MINUTE + 29_000, 20);
        up_at(&shared, &clock, &bytes, 2 * MINUTE + 31_000, 30);
        up_at(&shared, &clock, &bytes, 4 * MINUTE, 7);
        let mut reading = told(
            T,
            T + 3 * MINUTE,
            &[(T + 2 * MINUTE + 30_000, T + 3 * MINUTE, State::InUse)],
        );
        reading.screen = crate::states::Screen::On(Some(T + 2 * MINUTE + 30_000));
        shared.tell(&reading);
        bytes.down(&shared, 0, 0);
        // A later reading with the same moment the screen came on keeps the window as it is.
        let mut same = told(T + 3 * MINUTE, T + 3 * MINUTE + 1_000, &[]);
        same.screen = crate::states::Screen::On(Some(T + 2 * MINUTE + 30_000));
        shared.tell(&same);
        // At 22:14: every second in both windows; the one not told yet apart.
        let snapshot = shared.now_view(T + 4 * MINUTE + 1);
        let all = bytes_of(&snapshot, Some(UID));
        for window in [0, 1] {
            assert_eq!(all[window][3], [120, 0], "background, window {window}");
            assert_eq!(all[window][1], [30, 0], "in use, window {window}");
            assert_eq!(all[window][4], [7, 0], "not told yet, window {window}");
        }
        assert_eq!(all[2][1], [30, 0], "since the screen came on: in use");
        assert_eq!(
            all[2][3],
            [0, 0],
            "since the screen came on: the background was before"
        );
        assert_eq!(all[2][4], [7, 0]);
        // At 22:19:59, the minute of 22:10 is still in the 10 minutes; at 22:20, it is not.
        let at = |now| bytes_of(&shared.now_view(now), Some(UID));
        assert_eq!(at(T + 9 * MINUTE + 59_999)[0][3], [120, 0]);
        assert_eq!(at(T + 10 * MINUTE)[0][3], [20, 0]);
        assert_eq!(at(T + 10 * MINUTE)[1][3], [120, 0]);
        // At 23:10 the minute of 22:10 has left the hour too; the screen's window keeps what it had.
        let late = at(T + 60 * MINUTE);
        assert_eq!(
            (late[1][3], late[1][1], late[2][1]),
            ([20, 0], [30, 0], [30, 0])
        );
        // The screen comes on again: its window begins anew.
        let mut again = told(T + 3 * MINUTE, T + 61 * MINUTE, &[]);
        again.screen = crate::states::Screen::On(Some(T + 61 * MINUTE));
        shared.tell(&again);
        let snapshot = shared.now_view(T + 61 * MINUTE);
        assert_eq!(bytes_of(&snapshot, Some(UID))[2], [[0; 2]; COLUMNS]);
        assert_eq!(
            bytes_of(&snapshot, Some(UID))[1][3],
            [27, 0],
            "the 7 told since"
        );
        assert_eq!(snapshot.session, Some(T + 61 * MINUTE));
    }

    /// An app with no bytes left in any window is forgotten; its state now is read from the last second
    /// told.
    #[test]
    fn an_app_with_no_bytes_left_in_any_window_is_forgotten() {
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 0, 10);
        let mut reading = told(T, T + 2_000, &[(T + 1_000, T + 2_000, State::Notification)]);
        reading.screen = crate::states::Screen::Off;
        shared.tell(&reading);
        let snapshot = shared.now_view(T + 2_000);
        let app = app_of(&snapshot, Some(UID));
        assert_eq!(app.map(|a| a.now), Some(Some(NOTIFICATION)));
        assert_eq!(snapshot.known, Some(Known::States));
        assert_eq!(snapshot.told_until, T + 2_000);
        assert!(app_of(&shared.now_view(T + 59 * MINUTE), Some(UID)).is_some());
        assert!(app_of(&shared.now_view(T + 60 * MINUTE), Some(UID)).is_none());
        assert!(lock(&shared.activity).counts.apps.is_empty());
        // With the screen on since before, its window keeps the app.
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 0, 10);
        shared.tell(&told(T, T + 2_000, &[]));
        assert!(app_of(&shared.now_view(T + 600 * MINUTE), Some(UID)).is_some());
    }

    /// Each destination an app reached, as W3 named it, with its bytes in each window; flows to one name
    /// at several addresses are one destination, unnamed flows one per address; a chained app's flow
    /// whose destination stays out of the log adds to its app's bytes only, marked as through the tool.
    #[test]
    fn destinations_are_named_as_w3_names_them_and_a_chained_apps_are_not_kept() {
        let (shared, clock, _) = telling_at(T);
        let second = |id, destination: [u8; 4], name: Option<&str>| {
            let Some(bytes) = shared.record(Flow {
                destination: SocketAddr::from((destination, 443)),
                name: name.map(str::to_owned),
                named_by: if name.is_some() {
                    NamedBy::Dns
                } else {
                    NamedBy::Unknown
                },
                ..flow(id, Some(UID))
            }) else {
                unreachable!("an open flow is live")
            };
            bytes
        };
        let a = second(1, [198, 51, 100, 9], Some("www.example.com"));
        let b = second(2, [198, 51, 100, 10], Some("www.example.com"));
        let c = second(3, [192, 0, 2, 1], None);
        let d = second(4, [192, 0, 2, 2], None);
        for (bytes, n) in [(&a, 10), (&b, 20), (&c, 30), (&d, 40)] {
            up_at(&shared, &clock, bytes, 500, n);
        }
        clock.set(T + 1_000);
        a.down(&shared, 5, 0);
        // A chained app, its destinations left out of the log ("Log where these apps connect" off).
        let chained = 10_300;
        *lock(&shared.chain) = Some(Arc::new(crate::engine::Chain {
            proxy: SocketAddr::from(([127, 0, 0, 1], 10_808)),
            credentials: None,
            tool: 10_200,
            apps: Some(std::collections::HashSet::from([chained])),
            udp: true,
            log_destinations: false,
        }));
        let Some(hidden) = shared.record(flow(5, Some(chained))) else {
            unreachable!("an open flow is live")
        };
        up_at(&shared, &clock, &hidden, 1_200, 50);
        let Some(tool) = shared.record(flow(6, Some(10_200))) else {
            unreachable!("an open flow is live")
        };
        up_at(&shared, &clock, &tool, 1_300, 60);
        // Before any reading, the destinations show with their bytes not told yet.
        let early = shared.now_view(T + 1_500);
        let mine = app_of(&early, Some(UID)).map(|a| a.places.len());
        assert_eq!(mine, Some(3));
        let mut reading = told(T, T + 3_000, &[]);
        reading.intervals.push(Interval {
            uid: chained,
            from: T,
            until: T + 3_000,
            state: State::InUse,
        });
        shared.tell(&reading);
        let snapshot = shared.now_view(T + 3_000);
        let Some(app) = app_of(&snapshot, Some(UID)) else {
            unreachable!("the app is in the view")
        };
        // One name at two addresses is one destination, at the address of the flow placed last.
        let mut places: Vec<_> = app
            .places
            .iter()
            .map(|p| {
                let unnamed = p.flow.name.is_none();
                let address = unnamed.then(|| p.flow.destination.ip().to_string());
                (p.flow.name.clone(), address, p.bytes[0])
            })
            .collect();
        places.sort();
        assert_eq!(
            places,
            vec![
                (None, Some("192.0.2.1".into()), [30, 0]),
                (None, Some("192.0.2.2".into()), [40, 0]),
                (Some("www.example.com".into()), None, [30, 5]),
            ]
        );
        assert!(!app.tool && !app.through_tool);
        let Some(chained) = app_of(&snapshot, Some(chained)) else {
            unreachable!("the chained app is in the view")
        };
        assert!(chained.through_tool && chained.places.is_empty());
        assert_eq!(chained.bytes[0][1], [50, 0]);
        // The tool's own servers stay out too while the switch is off (decision 3, 2026-11-19); its bytes
        // stay, marked as the tool's, not as through it.
        let tool = app_of(&snapshot, Some(10_200)).map(|a| {
            let sent: u64 = a.bytes[0][..5].iter().map(|w| w[0]).sum();
            (a.tool, a.through_tool, a.places.len(), sent)
        });
        assert_eq!(tool, Some((true, false, 0, 60)));
        assert_eq!(lock(&shared.activity).counts.places, 3);
    }

    /// The tool's own destinations, its servers, show and are logged only while "Log where these apps
    /// connect" is on; turned off, they leave "Now" at once (ADR 0046, decision 3's tool row, decided
    /// 2026-11-19).
    #[test]
    fn the_tools_own_destinations_follow_the_switch() {
        let (shared, clock, _) = telling_at(T);
        *lock(&shared.chain) = Some(chain_of(UID, true));
        let Some(on) = shared.record(flow(1, Some(10_200))) else {
            unreachable!("an open flow is live")
        };
        up_at(&shared, &clock, &on, 500, 10);
        shared.tell(&told(T, T + 1_000, &[]));
        let places = |shared: &Shared, at| {
            app_of(&shared.now_view(at), Some(10_200))
                .map(|a| (a.tool, a.through_tool, a.servers_hidden, a.places.len()))
        };
        assert_eq!(
            places(&shared, T + 1_000),
            Some((true, false, false, 1)),
            "logged while on"
        );
        *lock(&shared.chain) = Some(chain_of(UID, false));
        shared.hide_chained();
        assert_eq!(
            places(&shared, T + 1_000),
            Some((true, false, true, 0)),
            "gone at once, and said to be"
        );
        let Some(off) = shared.record(flow(2, Some(10_200))) else {
            unreachable!("an open flow is live")
        };
        up_at(&shared, &clock, &off, 1_500, 20);
        shared.tell(&told(T + 1_000, T + 2_000, &[]));
        assert_eq!(places(&shared, T + 2_000), Some((true, false, true, 0)));
        clock.set(T + 3_000);
        shared.flush();
        for record in taken(&shared) {
            if let crate::log::Record::Segment { flow, start, .. } = record
                && start >= T + 1_000
            {
                assert!(
                    flow.destination.ip().is_unspecified() && flow.name.is_none(),
                    "{flow:?}"
                );
            }
        }
    }

    /// A chain that sends `uid` through the tool, its destinations logged or not.
    fn chain_of(uid: u32, log_destinations: bool) -> Arc<crate::engine::Chain> {
        Arc::new(crate::engine::Chain {
            proxy: SocketAddr::from(([127, 0, 0, 1], 10_808)),
            credentials: None,
            tool: 10_200,
            apps: Some(std::collections::HashSet::from([uid])),
            udp: true,
            log_destinations,
        })
    }

    /// A chain set on the engine that leaves an app's destinations out of the log drops them from "Now" at
    /// once (ADR 0046, decision 6, item 5; review b1 of W5's second part, engine, finding 1).
    #[test]
    fn a_chain_set_on_the_engine_drops_its_apps_destinations_at_once() {
        let (shared, clock, _) = telling_at(T);
        *lock(&shared.chain) = Some(chain_of(UID, true));
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 500, 50);
        shared.tell(&told(T, T + 1_000, &[]));
        let engine = crate::engine::Engine {
            shared: Arc::new(shared),
            stop: tokio::sync::watch::channel(false).0,
            network: tokio::sync::watch::channel(0).0,
            swaps: tokio::sync::mpsc::unbounded_channel().0,
            thread: None,
        };
        let places = |engine: &crate::engine::Engine| {
            let snapshot = engine.shared.now_view(T + 1_000);
            app_of(&snapshot, Some(UID)).map(|a| (a.places.len(), a.through_tool))
        };
        assert_eq!(places(&engine), Some((1, false)));
        engine.chain(Some((*chain_of(UID, false)).clone()));
        assert_eq!(places(&engine), Some((0, true)));
    }

    /// A connection that went directly, opened before its app was chained with its destinations left
    /// out, loses its destination in "Now" but is not marked as through the tool, which it never went
    /// through; the flows opened after the chain are (review b2 of W5's second part, N3). And the
    /// organisations looked up for the view are forgotten with the destinations (N8).
    #[test]
    fn a_direct_connection_from_before_the_chain_is_not_through_the_tool() {
        let (mut shared, clock, _) = telling_at(T);
        shared.organisations = Some(
            crate::organisations::Organisations::open(Box::new(
                crate::organisations::tests::sample(),
            ))
            .unwrap_or_else(|e| unreachable!("{e}")),
        );
        let direct = shared.record(Flow {
            destination: SocketAddr::from(([93, 184, 216, 34], 443)),
            ..flow(1, Some(UID))
        });
        let Some(direct) = direct else {
            unreachable!("an open flow is live")
        };
        up_at(&shared, &clock, &direct, 500, 50);
        shared.tell(&told(T, T + 1_000, &[]));
        let view = |shared: &Shared, at| {
            let snapshot = shared.now_view(at);
            app_of(&snapshot, Some(UID)).map(|a| (a.places.len(), a.through_tool, a.bytes[1][3]))
        };
        assert_eq!(view(&shared, T + 1_000), Some((1, false, [50, 0])));
        assert!(!lock(&shared.activity).counts.organisations.is_empty());
        *lock(&shared.chain) = Some(chain_of(UID, false));
        shared.hide_chained();
        assert!(
            lock(&shared.activity).counts.organisations.is_empty(),
            "forgotten"
        );
        up_at(&shared, &clock, &direct, 1_500, 20);
        shared.tell(&told(T + 1_000, T + 2_000, &[]));
        assert_eq!(
            view(&shared, T + 2_000),
            Some((0, false, [70, 0])),
            "direct, not through the tool"
        );
        // A flow opened now goes through the tool.
        let routed = open(&shared, 2);
        up_at(&shared, &clock, &routed, 2_500, 5);
        shared.tell(&told(T + 2_000, T + 3_000, &[]));
        assert_eq!(view(&shared, T + 3_000), Some((0, true, [75, 0])));
    }

    /// A destination reached first directly and then through the tool, under one name, marks its app
    /// through the tool when the switch hides it, from the last second through the tool (review b3 of W5's
    /// second part, R6: only the first flow's way was kept).
    #[test]
    fn a_destination_reached_later_through_the_tool_marks_it_so() {
        let (shared, clock, _) = telling_at(T);
        let direct = open(&shared, 1);
        up_at(&shared, &clock, &direct, 500, 10);
        *lock(&shared.chain) = Some(chain_of(UID, true));
        let routed = open(&shared, 2);
        up_at(&shared, &clock, &routed, 1_500, 30);
        shared.tell(&told(T, T + 2_000, &[]));
        let view = |shared: &Shared| {
            let snapshot = shared.now_view(T + 2_000);
            app_of(&snapshot, Some(UID)).map(|a| (a.places.len(), a.through_tool))
        };
        assert_eq!(view(&shared), Some((1, false)), "one destination, logged");
        *lock(&shared.chain) = Some(chain_of(UID, false));
        shared.hide_chained();
        assert_eq!(view(&shared), Some((0, true)));
    }

    /// A flow through a `WireGuard` tunnel (W7) is shown with its route: its destination with the tunnel's
    /// number while "Log where these apps connect" is on; with it off, no destination, and the app marked as
    /// through that tunnel. Never as through the tool.
    #[test]
    fn a_tunnelled_flow_is_shown_through_its_tunnel() {
        use super::super::{Configured, TunnelSetting};
        let (shared, clock, _) = telling_at(T);
        let text = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.77.0.2/32\n\
                    DNS = 10.77.0.1\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n\
                    AllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n";
        let Ok(config) = crate::wireguard::Config::parse(text.as_bytes()) else {
            unreachable!("refused")
        };
        let set = |log| TunnelSetting {
            tunnels: vec![Configured {
                id: 3,
                config: Arc::new(config.clone()),
                local_network: false,
            }],
            routes: std::collections::HashMap::from([(UID, 3), (UID + 1, 3)]),
            log_destinations: log,
            default: None,
            known: None,
        };
        shared.tunnels.set(&set(true));
        let Some(kept) = shared.record_tunnelled(flow(1, Some(UID)), 3) else {
            unreachable!("not live")
        };
        up_at(&shared, &clock, &kept, 500, 10);
        shared.tell(&told(T, T + 1_000, &[]));
        let snapshot = shared.now_view(T + 1_000);
        let app = app_of(&snapshot, Some(UID)).map(|a| {
            (
                a.places.iter().map(|p| p.flow.via).collect::<Vec<_>>(),
                a.through_tool,
                a.through_tunnel,
            )
        });
        assert_eq!(
            app,
            Some((vec![crate::engine::Via::Tunnel(3)], false, None))
        );
        shared.tunnels.set(&set(false));
        shared.hide_chained();
        let snapshot = shared.now_view(T + 1_000);
        let app = app_of(&snapshot, Some(UID)).map(|a| (a.places.len(), a.through_tunnel));
        assert_eq!(
            app,
            Some((0, Some(3))),
            "its destination left out when the switch goes off"
        );
        // Another app through the tunnel with the switch off from its first byte: its placed seconds mark it.
        let Some(hidden) = shared.record_tunnelled(flow(2, Some(UID + 1)), 3) else {
            unreachable!("not live")
        };
        up_at(&shared, &clock, &hidden, 1_500, 10);
        shared.tell(&told(T + 1_000, T + 2_000, &[]));
        let snapshot = shared.now_view(T + 2_000);
        let app = app_of(&snapshot, Some(UID + 1))
            .map(|a| (a.places.len(), a.through_tool, a.through_tunnel));
        assert_eq!(app, Some((0, false, Some(3))));
    }

    /// A connection is shown the way it was routed, not by the chain when it is recorded: one routed directly
    /// and recorded after a chain was set for its app, with its destinations left out, has no destination and
    /// is not through the tool; one routed through the tool and recorded after the chain was turned off is
    /// through it, and its records keep no destination (review b3 of W5's second part, R2).
    #[test]
    fn a_flow_is_shown_the_way_it_was_routed() {
        let (shared, clock, _) = telling_at(T);
        let view = |shared: &Shared, at| {
            let snapshot = shared.now_view(at);
            app_of(&snapshot, Some(UID)).map(|a| (a.places.len(), a.through_tool))
        };
        *lock(&shared.chain) = Some(chain_of(UID, false));
        let Some(direct) = shared.record_via(flow(1, Some(UID)), None) else {
            unreachable!("an open flow is live")
        };
        up_at(&shared, &clock, &direct, 500, 10);
        shared.tell(&told(T, T + 1_000, &[]));
        assert_eq!(
            view(&shared, T + 1_000),
            Some((0, false)),
            "direct, not through the tool"
        );
        *lock(&shared.chain) = None;
        let chain = chain_of(UID, false);
        let Some(routed) = shared.record_via(flow(2, Some(UID)), Some(&chain)) else {
            unreachable!("an open flow is live")
        };
        up_at(&shared, &clock, &routed, 1_500, 5);
        shared.tell(&told(T + 1_000, T + 2_000, &[]));
        assert_eq!(
            view(&shared, T + 2_000),
            Some((0, true)),
            "through the tool"
        );
        clock.set(T + 3_000);
        shared.flush();
        for record in std::mem::take(&mut *lock(&shared.pending_log)) {
            if let crate::log::Record::Segment { flow, .. } = record {
                assert!(flow.destination.ip().is_unspecified(), "{flow:?}");
            }
        }
    }

    /// Two flows to one name whose DNS answers named their addresses otherwise are two destinations (review
    /// b3 of W5's second part, fresh, n7: no test held the DNS name's part).
    #[test]
    fn one_name_with_two_dns_names_is_two_destinations() {
        let mut counts = Counts::default();
        for (id, dns_name) in [(1, "a.example"), (2, "b.example"), (3, "a.example")] {
            let to = Flow {
                named_by: NamedBy::Tls,
                dns_name: Some(dns_name.into()),
                ..flow(id, Some(UID))
            };
            counts.count(
                Some(UID),
                T / 1000,
                [1, 0, 0, 0],
                BACKGROUND,
                Seen::Flow(&to),
            );
        }
        assert_eq!(counts.apps[&Some(UID)].places.len(), 2);
    }

    /// "Through the tool" leaves with the windows: an app chained more than an hour ago, with no flow
    /// through the tool since, is no longer marked (review b2 of W5's second part, fresh, m7).
    #[test]
    fn through_the_tool_leaves_with_the_windows() {
        let (shared, clock, _) = telling_at(T);
        *lock(&shared.chain) = Some(chain_of(UID, false));
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 500, 5);
        shared.tell(&told(T, T + 1_000, &[]));
        // The screen came on again just after: the window since then holds no second through the tool.
        let mut later = told(T + 1_000, T + 2_000, &[]);
        later.screen = crate::states::Screen::On(Some(T + 2_000));
        shared.tell(&later);
        let marked = |at| app_of(&shared.now_view(at), Some(UID)).map(|a| a.through_tool);
        assert_eq!(marked(T + 1_000), Some(true));
        assert_eq!(marked(T + 9 * MINUTE), Some(true), "within the 10 minutes");
        assert_eq!(marked(T + 59 * MINUTE), Some(true), "within the hour");
        // Unchained, it sends directly at 59 minutes: past the hour it is in "Now" for those bytes alone.
        *lock(&shared.chain) = None;
        let direct = open(&shared, 2);
        up_at(&shared, &clock, &direct, 59 * MINUTE, 7);
        shared.tell(&told(T + 59 * MINUTE - 1_000, T + 59 * MINUTE + 1_000, &[]));
        assert_eq!(marked(T + 61 * MINUTE), Some(false), "past the hour");
    }

    /// The seconds not told yet of a chained app whose destinations are not logged count its bytes as
    /// through the tool, with no destination (review b1 of W5's second part, engine, finding 8).
    #[test]
    fn a_chained_apps_seconds_not_told_yet_show_no_destination() {
        let (shared, clock, _) = telling_at(T);
        *lock(&shared.chain) = Some(chain_of(UID, false));
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 500, 50);
        let snapshot = shared.now_view(T + 1_000);
        let app = app_of(&snapshot, Some(UID));
        assert_eq!(
            app.map(|a| (a.places.len(), a.through_tool, a.bytes[0][4])),
            Some((0, true, [50, 0]))
        );
    }

    /// Turning "Log where these apps connect" off drops a chained app's destinations from "Now" at once,
    /// keeping its bytes, marked as through the tool; a flow opened while it was on, still open or
    /// waiting for its state, adds no destination after, and its records after carry none (ADR 0046,
    /// decision 6, item 5; review b1 of W5's second part, engine, finding 1).
    #[test]
    fn turning_the_switch_off_drops_a_chained_apps_destinations_at_once() {
        let (shared, clock, _) = telling_at(T);
        *lock(&shared.chain) = Some(chain_of(UID, true));
        let open_flow = open(&shared, 1);
        let ended = open(&shared, 2);
        up_at(&shared, &clock, &open_flow, 500, 50);
        up_at(&shared, &clock, &ended, 600, 5);
        shared.finish(2);
        shared.tell(&told(T, T + 1_000, &[]));
        let places = |shared: &Shared, at| {
            let snapshot = shared.now_view(at);
            app_of(&snapshot, Some(UID)).map(|a| (a.places.len(), a.through_tool))
        };
        assert_eq!(
            places(&shared, T + 1_000),
            Some((1, false)),
            "logged while on"
        );
        // The second flow's segment waits for a second not told yet; the switch goes off.
        up_at(&shared, &clock, &open_flow, 1_500, 0);
        let other = open(&shared, 3);
        up_at(&shared, &clock, &other, 1_600, 7);
        shared.finish(3);
        *lock(&shared.chain) = Some(chain_of(UID, false));
        shared.hide_chained();
        assert_eq!(
            places(&shared, T + 2_000),
            Some((0, true)),
            "a destination left after the switch went off"
        );
        up_at(&shared, &clock, &open_flow, 2_500, 70);
        shared.tell(&told(T + 1_000, T + 3_000, &[]));
        assert_eq!(places(&shared, T + 3_000), Some((0, true)));
        let snapshot = shared.now_view(T + 3_000);
        let bytes = app_of(&snapshot, Some(UID)).map(|a| a.bytes[1][3]);
        assert_eq!(bytes, Some([50 + 5 + 7 + 70, 0]), "the bytes stay");
        clock.set(T + 4_000);
        shared.flush();
        for record in std::mem::take(&mut *lock(&shared.pending_log)) {
            if let crate::log::Record::Segment { flow, start, .. } = record
                && start >= T + 1_000
            {
                assert!(
                    flow.name.is_none() && flow.destination.ip().is_unspecified(),
                    "{flow:?}"
                );
            }
        }
    }

    /// A flow of no app, placed with no reading, keeps every byte counted in a second after a placing in
    /// that second (review b1 of W5's second part, engine, finding 3).
    #[test]
    fn a_flow_of_no_app_keeps_the_bytes_counted_after_a_placing_in_its_second() {
        let (shared, clock, _) = telling_at(T);
        let Some(bytes) = shared.record(flow(1, None)) else {
            unreachable!("an open flow is live")
        };
        up_at(&shared, &clock, &bytes, 100, 10);
        clock.set(T + 200);
        shared.tell(&told(T - 10_000, T - 2_000, &[]));
        up_at(&shared, &clock, &bytes, 300, 20);
        up_at(&shared, &clock, &bytes, 1_500, 30);
        clock.set(T + 4_000);
        shared.tell(&told(T - 2_000, T + 2_000, &[]));
        clock.set(T + 5_000);
        shared.flush();
        let snapshot = shared.now_view(T + 5_000);
        assert_eq!(bytes_of(&snapshot, None)[0][0], [60, 0]);
    }

    /// A clock set back into the second of a flow's latest mark: the bytes counted after reach "Now" too
    /// (finding 4); and set back by more than the windows, the windows hold the new clock's bytes, not the
    /// old clock's (finding 5).
    #[test]
    fn a_clock_set_back_keeps_the_new_bytes_in_the_windows() {
        let (shared, clock, _) = telling_at(T);
        let a = open(&shared, 1);
        let b = open(&shared, 2);
        up_at(&shared, &clock, &a, 100, 5);
        up_at(&shared, &clock, &b, 1_500, 7);
        up_at(&shared, &clock, &a, 400, 20);
        clock.set(T + 3_000);
        shared.flush();
        let snapshot = shared.now_view(T + 3_000);
        assert_eq!(
            bytes_of(&snapshot, Some(UID))[0][0],
            [32, 0],
            "a byte lost from the second set back into"
        );
        // Two hours back: the old clock's minute leaves the windows.
        let (shared, clock, _) = telling_at(T);
        let a = open(&shared, 1);
        up_at(&shared, &clock, &a, 100, 10);
        clock.set(T + 3_000);
        shared.tell(&told(T, T + 1_000, &[]));
        let back = T - 2 * 3_600_000;
        clock.set(back);
        a.up(&shared, 50, 0);
        clock.set(back + 3_000);
        let mut reading = told(back, back + 1_000, &[]);
        reading.screen = crate::states::Screen::On(Some(back));
        shared.tell(&reading);
        let snapshot = shared.now_view(back + 3_000);
        let all = bytes_of(&snapshot, Some(UID));
        assert_eq!((all[0][3], all[1][3]), ([50, 0], [50, 0]));
        assert_eq!(
            all[2][3],
            [50, 0],
            "since the screen came on, by the new clock"
        );
        // With no new moment the screen came on, the window since it came on, on the old clock, is forgotten
        // with what it held (review b3 of W5's second part, fresh, n7).
        let (shared, clock, _) = telling_at(T);
        let a = open(&shared, 1);
        up_at(&shared, &clock, &a, 100, 10);
        clock.set(T + 3_000);
        shared.tell(&told(T, T + 1_000, &[]));
        assert_eq!(
            bytes_of(&shared.now_view(T + 3_000), Some(UID))[2][3],
            [10, 0]
        );
        clock.set(back);
        a.up(&shared, 50, 0);
        clock.set(back + 3_000);
        let mut reading = told(back, back + 1_000, &[]);
        reading.screen = crate::states::Screen::On(None);
        shared.tell(&reading);
        let all = bytes_of(&shared.now_view(back + 3_000), Some(UID));
        assert_eq!((all[1][3], all[2][3]), ([50, 0], [0, 0]));
    }

    /// Bounded: one app more than [`APPS`] takes the place of the one with bytes the longest ago; one
    /// destination more than an app keeps, or all apps keep, takes the place of the one with bytes the
    /// longest ago.
    #[test]
    fn the_counts_stay_within_their_bounds() {
        let mut counts = Counts::default();
        let named = |id: u64, name: String| Flow {
            name: Some(name),
            ..flow(id, Some(UID))
        };
        for uid in 0..=u32::try_from(APPS).unwrap_or(u32::MAX) {
            let place = named(1, format!("app{uid}.example"));
            counts.count(
                Some(uid),
                1_000 + u64::from(uid),
                [1, 0, 0, 0],
                BACKGROUND,
                Seen::Flow(&place),
            );
        }
        assert_eq!(counts.apps.len(), APPS);
        assert!(!counts.apps.contains_key(&Some(0)), "the oldest gave way");
        assert_eq!(counts.places, APPS);
        let mut counts = Counts::default();
        for i in 0..=PLACES_PER_APP as u64 {
            let place = named(i, format!("{i}.example"));
            counts.count(
                Some(UID),
                1_000 + i,
                [1, 0, 0, 0],
                BACKGROUND,
                Seen::Flow(&place),
            );
        }
        let app = &counts.apps[&Some(UID)];
        assert_eq!(
            (app.places.len(), counts.places),
            (PLACES_PER_APP, PLACES_PER_APP)
        );
        assert!(
            !app.places
                .iter()
                .any(|p| p.flow.name.as_deref() == Some("0.example"))
        );
        let mut counts = Counts::default();
        for i in 0..=PLACES as u64 {
            let uid = u32::try_from(i / 100).unwrap_or(0);
            let place = named(i, format!("{i}.example"));
            counts.count(
                Some(uid),
                1_000 + i,
                [1, 0, 0, 0],
                BACKGROUND,
                Seen::Flow(&place),
            );
        }
        assert_eq!(counts.places, PLACES);
        let total: usize = counts.apps.values().map(|a| a.places.len()).sum();
        assert_eq!(total, PLACES);
        // An app's minutes reach back an hour at most.
        let mut counts = Counts::default();
        for minute in 0..200u64 {
            counts.count(Some(UID), minute * 60, [1, 0, 0, 0], IN_USE, Seen::Lookups);
            counts.count(Some(UID), minute * 60, [1, 0, 0, 0], IN_USE, Seen::Hidden);
        }
        assert_eq!(counts.apps[&Some(UID)].minutes.len(), 60);
    }

    /// What the live view costs to build and encode, with 100 apps of 20 destinations each over the
    /// hour and seconds not told yet in 200 open flows: printed, for ADR 0046's "How it is built". Run it
    /// in a release build: `cargo test -p datapavan-net --release --lib -- --ignored --nocapture
    /// what_the_live_view_costs`.
    #[test]
    #[ignore = "a measurement, not a check: run it in a release build"]
    fn what_the_live_view_costs() {
        use std::time::Instant;
        let (shared, clock, _) = telling_at(T);
        {
            let mut activity = lock(&shared.activity);
            for uid in 0..100u32 {
                for place in 0..20u64 {
                    let flow = Flow {
                        name: Some(format!("host{place}.example{uid}.com")),
                        ..flow(place, Some(10_000 + uid))
                    };
                    for minute in 0..60 {
                        let second = T / 1000 + minute * 60 + place;
                        activity.counts.count(
                            Some(10_000 + uid),
                            second,
                            [100, 1_000, 0, 0],
                            BACKGROUND,
                            Seen::Flow(&flow),
                        );
                    }
                }
            }
        }
        let flows: Vec<_> = (1..=200).map(|id| open(&shared, id)).collect();
        for second in 0..5u64 {
            clock.set(T + 3_600_000 + second * 1_000);
            for bytes in &flows {
                bytes.up(&shared, 100, 140);
            }
        }
        let started = Instant::now();
        let mut size = 0;
        for _ in 0..100 {
            size = crate::snapshot::encode(&shared.now_view(T + 3_605_000)).len();
        }
        let each = started.elapsed().as_secs_f64() * 1e3 / 100.0;
        println!("the live view: {each:.2} ms to build and encode, {size} bytes");
    }

    /// Seconds not told yet that hold only the tunnel's bytes, no byte of the app's own, show no app.
    #[test]
    fn seconds_of_the_tunnels_bytes_alone_show_no_app() {
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 1_000, 0);
        bytes.down(&shared, 0, 52);
        assert_eq!(lock(&bytes.marks).len(), 1);
        assert!(app_of(&shared.now_view(T + 2_000), Some(UID)).is_none());
    }

    /// A destination's network that changes, as a later flow to the same organisation's name in another
    /// network, has its organisation read again.
    #[test]
    fn a_destination_whose_network_changes_is_named_again() {
        use crate::owners::NetworkKind;
        let mut counts = Counts::default();
        let organisation = |asn| Flow {
            name: Some("Example Org".into()),
            named_by: NamedBy::Organisation,
            network: Some(Network {
                asn,
                kind: NetworkKind::Unlisted,
            }),
            ..flow(1, Some(UID))
        };
        let (shared, _, _) = telling_at(T);
        counts.count(
            Some(UID),
            T / 1000,
            [1, 0, 0, 0],
            BACKGROUND,
            Seen::Flow(&organisation(64_500)),
        );
        *lock(&shared.activity) = {
            let mut activity = super::super::activity::Activity::new(true);
            activity.counts = counts;
            activity
        };
        let asn = |snapshot: &Snapshot| {
            app_of(snapshot, Some(UID))
                .and_then(|a| a.places[0].organisation.as_ref().map(|o| o.0.asn))
        };
        assert_eq!(asn(&shared.now_view(T + 1_000)), Some(64_500));
        lock(&shared.activity).counts.count(
            Some(UID),
            T / 1000 + 1,
            [1, 0, 0, 0],
            BACKGROUND,
            Seen::Flow(&organisation(64_501)),
        );
        assert_eq!(asn(&shared.now_view(T + 2_000)), Some(64_501));
    }

    /// The organisation table read by a snapshot: how often, and how often while the engine's flows or
    /// counts were held.
    struct Probe {
        table: Vec<u8>,
        shared: std::sync::OnceLock<std::sync::Weak<Shared>>,
        reads: std::sync::atomic::AtomicUsize,
        held: std::sync::atomic::AtomicUsize,
    }

    impl crate::organisations::Source for Arc<Probe> {
        fn read_exact_at(&self, buffer: &mut [u8], offset: u64) -> std::io::Result<()> {
            use std::sync::atomic::Ordering::Relaxed;
            if let Some(shared) = self.shared.get().and_then(std::sync::Weak::upgrade) {
                self.reads.fetch_add(1, Relaxed);
                if shared.activity.try_lock().is_err() || shared.live.try_lock().is_err() {
                    self.held.fetch_add(1, Relaxed);
                }
            }
            self.table.read_exact_at(buffer, offset)
        }

        fn size(&self) -> std::io::Result<u64> {
            self.table.size()
        }
    }

    /// A snapshot looks organisations up with no lock of the engine held, at most
    /// [`LOOKUPS_PER_VIEW`] addresses at a time, and never again an address it looked up already (review
    /// b1 of W5's second part, engine, finding 7).
    #[test]
    fn a_snapshot_looks_organisations_up_outside_the_locks_a_few_at_a_time() {
        use std::sync::atomic::Ordering::Relaxed;
        let probe = Arc::new(Probe {
            table: crate::organisations::tests::sample(),
            shared: std::sync::OnceLock::new(),
            reads: std::sync::atomic::AtomicUsize::new(0),
            held: std::sync::atomic::AtomicUsize::new(0),
        });
        let (mut shared, _, _) = telling_at(T);
        shared.organisations = Some(
            crate::organisations::Organisations::open(Box::new(probe.clone()))
                .unwrap_or_else(|e| unreachable!("{e}")),
        );
        // 100 destinations of one app in the sample's network of Example Net.
        {
            let mut activity = lock(&shared.activity);
            for i in 0..100u8 {
                let to = Flow {
                    destination: SocketAddr::from(([93, 184, 216, i], 443)),
                    name: None,
                    named_by: NamedBy::Unknown,
                    ..flow(u64::from(i), Some(UID))
                };
                activity.counts.count(
                    Some(UID),
                    T / 1000,
                    [1, 0, 0, 0],
                    BACKGROUND,
                    Seen::Flow(&to),
                );
            }
        }
        let shared = Arc::new(shared);
        assert!(probe.shared.set(Arc::downgrade(&shared)).is_ok());
        let named = |snapshot: &Snapshot| {
            app_of(snapshot, Some(UID)).map_or(0, |app| {
                app.places
                    .iter()
                    .filter(|place| {
                        place.organisation.as_ref().map(|o| o.1.as_str())
                            == Some("Example Net, Inc.")
                    })
                    .count()
            })
        };
        assert_eq!(named(&shared.now_view(T + 1_000)), LOOKUPS_PER_VIEW);
        assert!(probe.reads.load(Relaxed) > 0);
        assert_eq!(named(&shared.now_view(T + 2_000)), 100);
        let reads = probe.reads.load(Relaxed);
        assert_eq!(named(&shared.now_view(T + 3_000)), 100);
        assert_eq!(probe.reads.load(Relaxed), reads, "looked up once");
        assert_eq!(probe.held.load(Relaxed), 0, "no read under a lock");
    }

    /// Minutes counted out of order are kept in order.
    #[test]
    fn minutes_added_out_of_order_stay_in_order() {
        let mut minutes: Minutes<u64> = VecDeque::new();
        for minute in [5, 3, 7, 3, 6, 1] {
            add_minute(&mut minutes, minute, |n| *n += 1);
        }
        assert_eq!(
            minutes,
            VecDeque::from([(1, 1), (3, 2), (5, 1), (6, 1), (7, 1)])
        );
        add_minute(&mut minutes, 61, |n| *n += 1);
        assert_eq!(
            minutes,
            VecDeque::from([(3, 2), (5, 1), (6, 1), (7, 1), (61, 1)])
        );
    }

    /// A reading of the states over `from` to `until`, every app in the background, with the screen as
    /// given and when it went off.
    fn screen_told(from: u64, until: u64, screen: crate::states::Screen, off: Option<u64>) -> Told {
        Told {
            screen,
            screen_off: off,
            ..told(from, until, &[])
        }
    }

    /// The window "while the screen was off" holds each app's bytes by state from the moment the screen
    /// went off to the moment it came on, a second counting where it began, and seconds placed after the
    /// screen came on included; it is kept until the screen next goes off, which begins a new one, and a
    /// reading that tells an older moment it went off changes nothing (W5's third part, the open list's
    /// fourth item).
    #[test]
    fn the_window_while_the_screen_was_off_holds_each_apps_bytes_by_state() {
        use crate::states::Screen;
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        let mut reading = told(T, T + 1_000, &[(T, T + 1_000, State::InUse)]);
        reading.screen = Screen::On(Some(T - 10_000));
        up_at(&shared, &clock, &bytes, 0, 10);
        up_at(&shared, &clock, &bytes, 1_500, 20);
        shared.tell(&reading);
        assert_eq!(shared.now_view(T + 1_500).off, None, "not off yet");
        // Off at 1.2 s: the second it went off in began before, so it is not the window's.
        up_at(&shared, &clock, &bytes, 2_500, 30);
        up_at(&shared, &clock, &bytes, 5_000, 40);
        shared.tell(&screen_told(
            T + 1_000,
            T + 3_000,
            Screen::Off,
            Some(T + 1_200),
        ));
        let snapshot = shared.now_view(T + 3_000);
        assert_eq!(snapshot.off, Some((T + 1_200, None)));
        assert_eq!(bytes_of(&snapshot, Some(UID))[OFF][3], [30, 0]);
        // On again at 8 s: the second 5 is placed after, and still counts in the window; the second 8 began
        // as the screen came on, so it is since the screen came on, not while it was off.
        up_at(&shared, &clock, &bytes, 8_000, 50);
        let mut on = screen_told(
            T + 3_000,
            T + 9_000,
            Screen::On(Some(T + 8_000)),
            Some(T + 1_200),
        );
        on.intervals.push(Interval {
            uid: UID,
            from: T + 8_000,
            until: T + 9_000,
            state: State::InUse,
        });
        shared.tell(&on);
        let snapshot = shared.now_view(T + 9_000);
        assert_eq!(snapshot.off, Some((T + 1_200, Some(T + 8_000))));
        let all = bytes_of(&snapshot, Some(UID));
        assert_eq!((all[OFF][3], all[OFF][1]), ([70, 0], [0, 0]));
        assert_eq!((all[2][1], all[2][3]), ([50, 0], [0, 0]));
        assert_eq!(
            (all[0][1], all[0][3]),
            ([60, 0], [90, 0]),
            "the 10 minutes hold every second, the one the screen went off in included"
        );
        // Told again, the same or an older moment it went off changes nothing.
        for off in [T + 1_200, T + 500] {
            shared.tell(&screen_told(
                T + 9_000,
                T + 9_500,
                Screen::On(Some(T + 8_000)),
                Some(off),
            ));
            assert_eq!(
                shared.now_view(T + 9_500).off,
                Some((T + 1_200, Some(T + 8_000)))
            );
        }
        // Off again: a new window, empty, in place of the last.
        shared.tell(&screen_told(
            T + 9_500,
            T + 12_000,
            Screen::Off,
            Some(T + 11_000),
        ));
        let snapshot = shared.now_view(T + 12_000);
        assert_eq!(snapshot.off, Some((T + 11_000, None)));
        assert_eq!(bytes_of(&snapshot, Some(UID))[OFF], [[0; 2]; COLUMNS]);
    }

    /// The screen went off and came on again within one reading: its window opens and closes with it.
    #[test]
    fn a_screen_off_and_on_within_one_reading_has_its_window() {
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 2_500, 30);
        shared.tell(&screen_told(
            T,
            T + 4_000,
            crate::states::Screen::On(Some(T + 3_000)),
            Some(T + 2_000),
        ));
        let snapshot = shared.now_view(T + 4_000);
        assert_eq!(snapshot.off, Some((T + 2_000, Some(T + 3_000))));
        assert_eq!(bytes_of(&snapshot, Some(UID))[OFF][3], [30, 0]);
    }

    /// The window while the screen was off is bounded as the others: one app more than [`APPS`] takes
    /// the place of the one with bytes the longest ago; and a clock set back past its end forgets it, while
    /// one that still runs and began before the new clock's now is kept.
    #[test]
    fn the_window_while_the_screen_was_off_is_bounded_and_follows_the_clock() {
        let mut counts = Counts::default();
        counts.screen_off(T);
        for uid in 0..=u32::try_from(APPS).unwrap_or(u32::MAX) {
            let to = flow(1, Some(uid));
            counts.count(
                Some(uid),
                T / 1000 + 1 + u64::from(uid),
                [1, 0, 0, 0],
                BACKGROUND,
                Seen::Flow(&to),
            );
        }
        let off = counts.off.as_ref().map(|off| off.apps.len());
        assert_eq!(off, Some(APPS));
        assert!(
            counts
                .off
                .as_ref()
                .is_some_and(|off| !off.apps.contains_key(&Some(0)))
        );
        counts.set_back(T + 30_000);
        assert!(counts.off.is_some(), "still off, from before the new clock");
        counts.screen_on(T + 60_000);
        counts.set_back(T + 59_999);
        assert!(counts.off.is_none(), "its end is past the new clock");
        // Exactly at the new clock's now, it stays.
        let mut counts = Counts::default();
        counts.screen_off(T);
        counts.screen_on(T + 60_000);
        counts.set_back(T + 60_000);
        assert!(counts.off.is_some());
    }

    /// The edges of the window while the screen was off: it ends where the screen came on, once, even when
    /// it went off and came on in one millisecond, and a screen-on told again later does not move its end;
    /// a second not told yet that begins as the screen goes off is in it, and one that begins as it comes
    /// on is not.
    #[test]
    fn the_window_while_the_screen_was_off_has_sharp_edges() {
        let mut counts = Counts::default();
        counts.screen_off(T);
        counts.screen_on(T);
        assert_eq!(counts.off.as_ref().map(|off| off.until), Some(Some(T)));
        let mut counts = Counts::default();
        counts.screen_off(T);
        counts.screen_on(T + 5_000);
        counts.screen_on(T + 9_000);
        assert_eq!(
            counts.off.as_ref().map(|off| off.until),
            Some(Some(T + 5_000)),
            "a later screen-on with no screen-off between does not move its end"
        );
        // Seconds not told yet at the edges.
        let (shared, clock, _) = telling_at(T);
        let bytes = open(&shared, 1);
        up_at(&shared, &clock, &bytes, 0, 1);
        shared.tell(&screen_told(
            T - 1_000,
            T,
            crate::states::Screen::Off,
            Some(T),
        ));
        up_at(&shared, &clock, &bytes, 2_000, 2);
        let off = bytes_of(&shared.now_view(T + 2_500), Some(UID))[OFF][NOT_YET];
        assert_eq!(off, [3, 0], "both seconds begin while it is off");
        lock(&shared.activity).counts.screen_on(T + 2_000);
        let all = bytes_of(&shared.now_view(T + 2_500), Some(UID));
        assert_eq!((all[OFF][NOT_YET], all[2][NOT_YET]), ([1, 0], [2, 0]));
    }

    /// Bytes in no state count by why, in each window: no usage access, no events, told too late, no app,
    /// not told, each apart, and together they are the column of no state (W5's third part, the open list's
    /// fifth item).
    #[test]
    fn bytes_in_no_state_count_by_why_in_each_window() {
        use crate::states::Unknown;
        let (shared, _, _) = telling_at(T);
        let mut counts = Counts::default();
        counts.screen_on(T - 20 * MINUTE);
        counts.screen_off(T - 30 * MINUTE);
        let to = flow(1, Some(UID));
        let reasons = [
            Unknown::NoAccess,
            Unknown::Locked,
            Unknown::Late,
            Unknown::NoApp,
            Unknown::NotTold,
        ];
        for (n, why) in (1..).zip(reasons) {
            // Now, and 15 minutes ago: in the hour, not in the 10 minutes; and before the screen came on.
            for (second, more) in [
                (T / 1000, 0),
                (T / 1000 - 15 * 60, 100),
                (T / 1000 - 25 * 60, 1_000),
            ] {
                counts.count(
                    Some(UID),
                    second,
                    [n + more, n, 0, 0],
                    Placed::Unknown(why),
                    Seen::Flow(&to),
                );
            }
        }
        counts.count(
            Some(UID),
            T / 1000,
            [7, 0, 0, 0],
            BACKGROUND,
            Seen::Flow(&to),
        );
        lock(&shared.activity).counts = counts;
        let all = bytes_of(&shared.now_view(T + 1_000), Some(UID));
        for (r, n) in (0..5).zip(1..) {
            assert_eq!(all[0][5 + r], [n, n], "10 minutes, why {r}");
            assert_eq!(all[1][5 + r], [3 * n + 1_100, 3 * n], "the hour, why {r}");
            assert_eq!(
                all[2][5 + r],
                [2 * n + 100, 2 * n],
                "since the screen came on, why {r}"
            );
            assert_eq!(
                all[OFF][5 + r],
                [3 * n + 1_100, 3 * n],
                "while the screen was off, why {r}"
            );
        }
        assert_eq!(all[0][0], [15, 15], "no state is the sum of its whys");
        assert_eq!(all[0][3], [7, 0]);
        assert_eq!(all[1][0], [3 * 15 + 5 * 1_100, 3 * 15]);
        // The screen comes on again: its window's whys begin anew too.
        lock(&shared.activity).counts.screen_on(T + 500);
        let all = bytes_of(&shared.now_view(T + 1_000), Some(UID));
        assert_eq!(all[2], [[0; 2]; COLUMNS]);
        // A clock set back forgets the whys of the minutes later than its own, and of the window since
        // the screen came on if that came on later.
        let (shared, _, _) = telling_at(T);
        let mut counts = Counts::default();
        counts.screen_on(T - 20 * MINUTE);
        counts.count(
            Some(UID),
            T / 1000 - 25 * 60,
            [1, 1, 0, 0],
            NOT_TOLD,
            Seen::Flow(&to),
        );
        counts.count(
            Some(UID),
            T / 1000 - 60,
            [2, 2, 0, 0],
            NOT_TOLD,
            Seen::Flow(&to),
        );
        counts.set_back(T - 30 * MINUTE);
        counts.count(
            Some(UID),
            T / 1000 - 31 * 60,
            [9, 0, 0, 0],
            BACKGROUND,
            Seen::Flow(&to),
        );
        lock(&shared.activity).counts = counts;
        let all = bytes_of(&shared.now_view(T - 30 * MINUTE), Some(UID));
        assert_eq!(all[1][9], [0, 0], "the minutes later than the new clock's");
        assert_eq!(
            all[2][9],
            [0, 0],
            "the window since the screen came on was of the old clock"
        );
        assert_eq!(all[1][3], [9, 0]);
    }

    /// Clearing the live memory forgets every app's bytes in every window, its destinations, the window
    /// while the screen was off and the organisations looked up, and keeps the moment the screen came on;
    /// seconds before it, told later, stay out, while an open flow's seconds after it count again; the
    /// window it forgot is not opened anew by a reading that tells it again (ADR 0047, decision 3; the open
    /// list's first two items).
    #[test]
    fn clearing_the_live_memory_forgets_every_window_and_keeps_out_what_came_before() {
        use crate::states::Screen;
        let (mut shared, clock, _) = telling_at(T);
        shared.organisations = Some(
            crate::organisations::Organisations::open(Box::new(
                crate::organisations::tests::sample(),
            ))
            .unwrap_or_else(|e| unreachable!("{e}")),
        );
        let bytes = shared.record(Flow {
            destination: SocketAddr::from(([93, 184, 216, 34], 443)),
            ..flow(1, Some(UID))
        });
        let Some(bytes) = bytes else {
            unreachable!("an open flow is live")
        };
        up_at(&shared, &clock, &bytes, 500, 10);
        up_at(&shared, &clock, &bytes, 1_500, 20);
        shared.tell(&screen_told(
            T,
            T + 2_000,
            Screen::On(Some(T + 1_500)),
            Some(T + 500),
        ));
        // The second 2 is counted, not told yet, when the memory is cleared at 2.5 s.
        up_at(&shared, &clock, &bytes, 2_200, 30);
        let before = shared.now_view(T + 2_400);
        assert!(app_of(&before, Some(UID)).is_some() && before.off.is_some());
        assert!(!lock(&shared.activity).counts.organisations.is_empty());
        lock(&shared.activity).counts.clear(T + 2_500);
        let cleared = shared.now_view(T + 2_500);
        assert!(cleared.apps.is_empty(), "{:?}", cleared.apps);
        assert_eq!(cleared.off, None);
        assert_eq!(
            cleared.session,
            Some(T + 1_500),
            "the moment the screen came on is kept"
        );
        // The second 2, told now, stays out; the second 3, counted after, is in, with its destination.
        up_at(&shared, &clock, &bytes, 3_200, 40);
        assert_eq!(
            app_of(&shared.now_view(T + 3_300), Some(UID)).map(|a| a.bytes[0][4]),
            Some([40, 0]),
            "not told yet: only what came after"
        );
        shared.tell(&screen_told(
            T + 2_000,
            T + 4_000,
            Screen::On(Some(T + 1_500)),
            Some(T + 500),
        ));
        let snapshot = shared.now_view(T + 4_000);
        let app = app_of(&snapshot, Some(UID));
        assert_eq!(
            app.map(|a| (a.bytes[0][3], a.places.len())),
            Some(([40, 0], 1))
        );
        assert_eq!(
            snapshot.off, None,
            "the window it forgot is not opened anew"
        );
        // The flow stays open: its next seconds count too, and the log still gets every one.
        assert!(lock(&shared.live).contains_key(&1));
        clock.set(T + 5_000);
        shared.flush();
        let logged: u64 = taken(&shared)
            .iter()
            .filter_map(|record| match record {
                crate::log::Record::Segment { bytes, .. } => Some(bytes[0]),
                crate::log::Record::Lookups { .. } => None,
            })
            .sum();
        assert_eq!(logged, 100, "what is held for the log is the log's");
        // A screen that goes off after the clear opens a window of its own.
        shared.tell(&screen_told(
            T + 4_000,
            T + 6_000,
            Screen::Off,
            Some(T + 5_500),
        ));
        assert_eq!(shared.now_view(T + 6_000).off, Some((T + 5_500, None)));
    }

    /// The whys never exceed the column of no state, in any window: after a clock set back to before the
    /// app's newest minute, a minute in no state that left the app's minutes left its whys with it (review c1
    /// of W5's third part, engine, finding 3: the hour's whys held 3 bytes, its column of no state 0).
    #[test]
    fn the_whys_leave_with_their_minute() {
        let to = flow(1, Some(UID));
        let (shared, _, _) = telling_at(T);
        let mut counts = Counts::default();
        let s = T / 1000;
        counts.count(
            Some(UID),
            s - 3_600,
            [3, 0, 0, 0],
            NOT_TOLD,
            Seen::Flow(&to),
        );
        counts.count(
            Some(UID),
            s - 1_800,
            [4, 0, 0, 0],
            BACKGROUND,
            Seen::Flow(&to),
        );
        counts.count(Some(UID), s, [7, 0, 0, 0], BACKGROUND, Seen::Flow(&to));
        counts.set_back(T - MINUTE);
        lock(&shared.activity).counts = counts;
        let all = bytes_of(&shared.now_view(T - MINUTE), Some(UID));
        for (window, columns) in all.iter().enumerate() {
            let whys: u64 = columns[REASONS..].iter().map(|ways| ways[0]).sum();
            assert_eq!(whys, columns[0][0], "window {window}");
        }
    }

    /// A clear, then a clock set back: what is counted after shows at once, and a screen-off after opens its
    /// window (review c1 of W5's third part, engine, finding 1: both waited for the new clock to pass the
    /// clear's moment, as long as the set back).
    #[test]
    fn a_clock_set_back_after_a_clear_keeps_counting() {
        let to = flow(1, Some(UID));
        let mut counts = Counts::default();
        counts.screen_off(T + 50 * MINUTE);
        counts.clear(T + 60 * MINUTE);
        counts.set_back(T);
        counts.count(
            Some(UID),
            T / 1000 + 10,
            [5, 0, 0, 0],
            BACKGROUND,
            Seen::Flow(&to),
        );
        assert!(
            counts.apps.contains_key(&Some(UID)),
            "the bytes after the set back count"
        );
        counts.screen_off(T + 5 * MINUTE);
        assert_eq!(
            counts.off.as_ref().map(|off| off.from),
            Some(T + 5 * MINUTE)
        );
    }

    /// A window a clock set back forgot is not opened anew, empty, when the readings tell its moments again,
    /// moved back with the clock; a later screen-off opens one (finding 2).
    #[test]
    fn a_window_a_clock_set_back_forgot_stays_forgotten() {
        let to = flow(1, Some(UID));
        let mut counts = Counts::default();
        counts.screen_off(T);
        counts.count(
            Some(UID),
            T / 1000 + 5,
            [30, 0, 0, 0],
            BACKGROUND,
            Seen::Flow(&to),
        );
        counts.screen_on(T + 10 * MINUTE);
        counts.set_back(T + 5 * MINUTE);
        assert!(counts.off.is_none());
        // The network part's Kotlin side moves both moments back by the set back, 15 minutes, and tells them again.
        counts.screen_off(T - 15 * MINUTE);
        counts.screen_on(T - 5 * MINUTE);
        assert!(
            counts.off.is_none(),
            "an empty window, saying no app sent anything"
        );
        counts.screen_off(T + 6 * MINUTE);
        assert_eq!(
            counts.off.as_ref().map(|off| off.from),
            Some(T + 6 * MINUTE)
        );
    }

    /// The window while the screen was off begins no earlier than the engine began counting: the network part started
    /// with the screen off, its first reading telling a screen-off long before (finding 6); and a screen-on
    /// told before a running window's start does not end it (nit 1).
    #[test]
    fn the_window_begins_no_earlier_than_counting() {
        let mut counts = Counts::default();
        counts.begin(T + 4 * 60 * MINUTE);
        counts.begin(T + 5 * 60 * MINUTE);
        counts.screen_off(T);
        assert_eq!(
            counts.off.as_ref().map(|off| off.from),
            Some(T + 4 * 60 * MINUTE),
            "kept from the first engine"
        );
        counts.screen_off(T);
        counts.screen_on(T + 60 * MINUTE);
        assert_eq!(
            counts.off.as_ref().map(|off| off.until),
            Some(None),
            "a screen-on before it began"
        );
        counts.screen_on(T + 8 * 60 * MINUTE);
        assert_eq!(
            counts.off.as_ref().map(|off| off.until),
            Some(Some(T + 8 * 60 * MINUTE))
        );
        // A clear begins counting anew; a set back brings the moment down to the new clock.
        counts.clear(T + 9 * 60 * MINUTE);
        counts.screen_off(T + 9 * 60 * MINUTE + 1);
        assert_eq!(
            counts.off.as_ref().map(|off| off.from),
            Some(T + 9 * 60 * MINUTE + 1)
        );
        counts.set_back(T);
        counts.screen_off(T + 1);
        assert_eq!(counts.off.as_ref().map(|off| off.from), Some(T + 1));
    }

    /// The first second counted after a clear is the first that begins at or after it: a second the clear
    /// falls within began before, and stays out.
    #[test]
    fn a_clear_within_a_second_keeps_that_second_out() {
        let mut counts = Counts::default();
        counts.clear(T + 1);
        assert!(!counts.counted(T / 1000));
        assert!(counts.counted(T / 1000 + 1));
        counts.clear(T + 1_000);
        assert!(counts.counted(T / 1000 + 1));
        assert!(!counts.counted(T / 1000));
        assert!(Counts::default().counted(0), "never cleared");
    }

    /// Where the fixture the network part's Kotlin side reads is kept (`SnapshotTest`).
    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../android/network/src/test/resources/org/visadahyu/datapavan/network/activity/snapshot.hex"
    );

    /// The fixture the network part's Kotlin side reads is what the engine writes, byte for byte, as for the log
    /// (`logbook`): from an engine's own counts, of an app placed in each state, a chained app, the tool
    /// and flows of no app, read with no usage access at the end.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn the_kotlin_sides_snapshot_fixture_is_what_the_engine_writes() -> std::io::Result<()> {
        let platform = Arc::new(Telling::default());
        let clock = super::super::clock::ManualClock::at(T);
        let mut shared = shared_with(platform);
        shared.clock = clock.clone();
        // "Log where these apps connect" on: only then does a place hold where an app asked its proxy to go.
        shared.tunnels.set(&crate::engine::TunnelSetting {
            log_destinations: true,
            ..crate::engine::TunnelSetting::default()
        });
        let bytes = open(&shared, 1);
        // A second app's flow through a SOCKS5 proxy its bytes declared (version 4, ADR 0052).
        let Some(proxied) = shared.record(Flow {
            destination: SocketAddr::from(([203, 0, 113, 5], 1080)),
            name: Some("example.org".into()),
            named_by: NamedBy::Proxy,
            proxy: Some(Box::new(crate::engine::Proxied {
                kind: crate::proxies::Kind::Socks5,
                setting: false,
                password: true,
                outside_maker: false,
                asked: Some((crate::proxies::Asked::Name("example.org".into()), 443)),
                proxy_name: Some("proxy.example.net".into()),
                organisation: Some("Hetzner Online GmbH".into()),
                cover: None,
                left_out: false,
                trackers: vec![312],
            })),
            ..flow(3, Some(UID + 1))
        }) else {
            unreachable!("an open flow is live")
        };
        proxied.up(&shared, 60, 100);
        for (at, n) in [(0, 100), (1_000, 200), (2_000, 300), (3_000, 400)] {
            up_at(&shared, &clock, &bytes, at, n);
        }
        clock.set(T + 3_500);
        bytes.down(&shared, 1_000, 0);
        let Some(none) = shared.record(Flow {
            destination: SocketAddr::from(([192, 0, 2, 7], 853)),
            name: Some("dns.example".into()),
            named_by: NamedBy::Tls,
            dns_name: Some("other.example".into()),
            ech: crate::engine::Ech::Offered,
            dns: crate::engine::DnsUse::Encrypted,
            resolver: Some("sample".into()),
            protocol: crate::packet::UDP,
            came_in: true,
            ..flow(2, None)
        }) else {
            unreachable!("an open flow is live")
        };
        none.up(&shared, 50, 0);
        // The readings come once those seconds are over.
        clock.set(T + 6_000);
        shared.tell(&Told {
            from: T,
            until: T + 3_000,
            known: Known::States,
            screen: crate::states::Screen::On(Some(T + 1_000)),
            // The screen was off for a minute before it came on: the first second falls in that window.
            screen_off: Some(T - 59_000),
            intervals: vec![
                Interval {
                    uid: UID,
                    from: T,
                    until: T + 1_000,
                    state: State::InUse,
                },
                Interval {
                    uid: UID,
                    from: T + 1_000,
                    until: T + 2_000,
                    state: State::Notification,
                },
            ],
        });
        shared.tell(&Told {
            from: T + 3_000,
            until: T + 3_000,
            known: Known::NoAccess,
            screen: crate::states::Screen::Off,
            screen_off: None,
            intervals: Vec::new(),
        });
        let snapshot = shared.now_view(T + 4_000);
        let all = bytes_of(&snapshot, Some(UID));
        assert_eq!(
            (all[0][1], all[0][2], all[0][3], all[0][4]),
            ([100, 0], [200, 0], [300, 0], [400, 1_000])
        );
        assert_eq!(all[2][1], [0, 0], "before the screen came on");
        assert_eq!(all[3][1], [100, 0], "while the screen was off");
        assert_eq!(snapshot.off, Some((T - 59_000, Some(T + 1_000))));
        assert_eq!(bytes_of(&snapshot, None)[0][0], [50, 0]);
        assert_eq!(bytes_of(&snapshot, None)[0][8], [50, 0], "no app");
        let mut text = String::from(
            "# The network part's live view: one snapshot as the engine writes it (core/net/src/snapshot.rs,\n\
             # version 4), in hex. Written by the engine's test the_kotlin_sides_snapshot_fixture_is_what_the_engine_writes\n\
             # (core/net/src/engine/now.rs), which fails when the engine writes otherwise; run it with\n\
             # DATAPAVAN_WRITE_FIXTURE=1 to write it anew. Read by SnapshotTest. Not edited by hand.\n",
        );
        for line in crate::snapshot::encode(&snapshot).chunks(48) {
            text.extend(line.iter().map(|b| format!("{b:02x}")));
            text.push('\n');
        }
        if std::env::var_os("DATAPAVAN_WRITE_FIXTURE").is_some() {
            if let Some(folder) = std::path::Path::new(FIXTURE).parent() {
                std::fs::create_dir_all(folder)?;
            }
            std::fs::write(FIXTURE, &text)?;
        }
        let kept = std::fs::read_to_string(FIXTURE)?;
        assert!(
            kept == text,
            "{FIXTURE} is not what the engine writes: run this test with DATAPAVAN_WRITE_FIXTURE=1, then \
             the Kotlin side's SnapshotTest"
        );
        Ok(())
    }

    /// A flow of the app `uid` through a SOCKS5 proxy at `203.0.113.n:1080`, named `proxy-n.example.net` by DNS: an
    /// app's own proxy's first hop in full, as "Now" shows it while the switch is off, with no destination.
    fn through_proxy(id: u64, uid: u32, n: u8) -> Flow {
        let name = format!("proxy-{n}.example.net");
        Flow {
            destination: SocketAddr::from(([203, 0, 113, n], 1080)),
            name: Some(name.clone()),
            named_by: NamedBy::Dns,
            proxy: Some(Box::new(crate::engine::Proxied {
                kind: crate::proxies::Kind::Socks5,
                setting: false,
                password: true,
                outside_maker: false,
                asked: None,
                proxy_name: Some(name),
                organisation: None,
                cover: None,
                left_out: false,
                trackers: Vec::new(),
            })),
            ..flow(id, Some(uid))
        }
    }

    fn recorded(shared: &Shared, flow: Flow) -> Arc<super::super::logbook::FlowBytes> {
        let Some(bytes) = shared.record(flow) else {
            unreachable!("an open flow is live")
        };
        bytes
    }

    /// Whether a place's flow has the log's left-out shape: an own proxy's kind, and no address or name.
    fn stripped(flow: &Flow) -> bool {
        flow.destination.ip().is_unspecified()
            && flow.name.is_none()
            && flow
                .proxy
                .as_ref()
                .is_some_and(|p| p.left_out && p.proxy_name.is_none())
    }

    /// The places of the app `uid` as the counts hold them, read with no view, which sweeps.
    fn counted_places(shared: &Shared, uid: u32) -> Vec<Flow> {
        lock(&shared.activity)
            .counts
            .apps
            .get(&Some(uid))
            .map(|app| app.places.iter().map(|p| p.flow.clone()).collect())
            .unwrap_or_default()
    }

    /// The places of the app `uid` in the view at `now`, which sweeps first.
    fn shown_places(shared: &Shared, uid: u32, now: u64) -> Vec<PlaceNow> {
        shared
            .now_view(now)
            .apps
            .into_iter()
            .find(|app| app.uid == Some(uid))
            .map(|app| app.places)
            .unwrap_or_default()
    }

    /// A reading from `from` to `until` with the screen on since `since`: `UID` in use throughout.
    fn on_since(from: u64, until: u64, since: u64) -> Told {
        let mut reading = told(from, until, &[(from, until, State::InUse)]);
        reading.screen = crate::states::Screen::On(Some(since));
        reading
    }

    /// One first hop placed in "Now" with the screen on since `screen_on`, and its flow ended: the shared state
    /// and its clock.
    fn ended_first_hop(screen_on: u64) -> (Shared, Arc<super::super::clock::ManualClock>) {
        let (shared, clock, _) = telling_at(T);
        let bytes = recorded(&shared, through_proxy(1, UID, 5));
        up_at(&shared, &clock, &bytes, 500, 10);
        clock.set(T + 1_500);
        shared.tell(&on_since(T, T + 1_000, screen_on));
        assert!(own_first_hop(
            &shown_places(&shared, UID, T + 1_500)[0].flow
        ));
        shared.finish(1);
        (shared, clock)
    }

    /// Test 11 (W1, W4, W5): a first hop stays in full until ten minutes after its connection ends, by the time
    /// since the phone started; then it is stripped, merged into the app's stripped place of the same kind and
    /// facts with the bytes of both in every window, and its address's organisation leaves the view's memory.
    #[test]
    fn a_first_hop_is_shown_in_full_for_ten_minutes_after_its_connection_ends() {
        let (shared, clock, _) = telling_at(T);
        let one = recorded(&shared, through_proxy(1, UID, 5));
        let two = recorded(&shared, through_proxy(2, UID, 6));
        up_at(&shared, &clock, &one, 500, 10);
        up_at(&shared, &clock, &two, 600, 20);
        clock.set(T + 1_500);
        shared.tell(&on_since(T, T + 1_000, T));
        assert_eq!(shown_places(&shared, UID, T + 1_500).len(), 2);
        let first: std::net::IpAddr = [203, 0, 113, 5].into();
        assert!(
            lock(&shared.activity)
                .counts
                .organisations
                .contains_key(&first)
        );
        shared.finish(1);
        shared.finish(2);
        let shown = u64::try_from(SHOWN.as_millis()).unwrap_or(u64::MAX);
        clock.pass(shown - 1_000);
        let places = shown_places(&shared, UID, clock.wall_ms());
        assert!(
            places.len() == 2 && places.iter().all(|p| own_first_hop(&p.flow)),
            "9 min 59 s after: {places:?}"
        );
        clock.pass(1_000);
        let places = shown_places(&shared, UID, clock.wall_ms());
        assert_eq!(places.len(), 1, "merged: {places:?}");
        assert!(stripped(&places[0].flow), "{places:?}");
        assert_eq!(
            (places[0].bytes[1], places[0].bytes[2]),
            ([30, 0], [30, 0]),
            "the hour's and the screen-on's bytes of both"
        );
        let counted = counted_places(&shared, UID);
        assert!(counted.len() == 1 && stripped(&counted[0]));
        let organisations = &lock(&shared.activity).counts.organisations;
        assert!(
            !organisations.contains_key(&first)
                && !organisations.contains_key(&std::net::IpAddr::from([203, 0, 113, 6]))
        );
    }

    /// Test 12 (W3): a quiet flow keeps its first hop in full while it is open, however long, and for ten minutes
    /// after it ends.
    #[test]
    fn a_quiet_open_flow_keeps_its_first_hop_in_full() {
        let (shared, clock, _) = telling_at(T);
        let bytes = recorded(&shared, through_proxy(1, UID, 5));
        up_at(&shared, &clock, &bytes, 500, 10);
        clock.set(T + 1_500);
        shared.tell(&on_since(T, T + 1_000, T));
        clock.pass(30 * MINUTE);
        assert!(
            own_first_hop(&shown_places(&shared, UID, clock.wall_ms())[0].flow),
            "open and quiet"
        );
        shared.finish(1);
        clock.pass(10 * MINUTE - 1_000);
        assert!(own_first_hop(
            &shown_places(&shared, UID, clock.wall_ms())[0].flow
        ));
        clock.pass(1_000);
        assert!(stripped(
            &shown_places(&shared, UID, clock.wall_ms())[0].flow
        ));
    }

    /// Test 13 (W9): with no view across a sleep, the next reading of the states strips what is due, in memory.
    #[test]
    fn a_reading_strips_a_first_hop_past_its_window_with_no_view() {
        let (shared, clock) = ended_first_hop(T);
        clock.pass(11 * MINUTE);
        shared.tell(&on_since(T + 1_000, clock.wall_ms(), T));
        let counted = counted_places(&shared, UID);
        assert!(counted.len() == 1 && stripped(&counted[0]), "{counted:?}");
        assert!(stripped(
            &shown_places(&shared, UID, clock.wall_ms())[0].flow
        ));
    }

    /// Test 14 (W2): the window runs on the time since the phone started, not on the wall clock: set forward a day,
    /// the place stays in full until ten minutes after the end; set back an hour, it is stripped ten minutes after.
    /// The screen came on before the flow, so that its window keeps the place through either.
    #[test]
    fn the_window_runs_on_the_boot_clock() {
        let (shared, clock) = ended_first_hop(T - 2 * 60 * MINUTE);
        clock.set(T + 24 * 60 * MINUTE);
        assert!(
            own_first_hop(&shown_places(&shared, UID, clock.wall_ms())[0].flow),
            "a day ahead"
        );
        clock.pass(10 * MINUTE - 2_000);
        assert!(own_first_hop(
            &shown_places(&shared, UID, clock.wall_ms())[0].flow
        ));
        clock.pass(2_000);
        assert!(stripped(
            &shown_places(&shared, UID, clock.wall_ms())[0].flow
        ));
        let (shared, clock) = ended_first_hop(T - 2 * 60 * MINUTE);
        clock.set(T - 60 * MINUTE);
        assert!(own_first_hop(&counted_places(&shared, UID)[0]));
        assert!(
            own_first_hop(&shown_places(&shared, UID, clock.wall_ms())[0].flow),
            "an hour back"
        );
        clock.pass(11 * MINUTE);
        assert!(stripped(
            &shown_places(&shared, UID, clock.wall_ms())[0].flow
        ));
    }

    /// Test 15 (W6): a segment held for its states, of a flow that ended, is stripped once its window ends: the
    /// view's place of its seconds not told yet, and the record the log gets.
    #[test]
    fn a_held_segment_past_its_window_is_stripped() {
        let (shared, clock, _) = telling_at(T);
        let bytes = recorded(&shared, through_proxy(1, UID, 5));
        up_at(&shared, &clock, &bytes, 500, 10);
        shared.finish(1);
        assert!(
            own_first_hop(&shown_places(&shared, UID, T + 1_000)[0].flow),
            "not told yet, in full"
        );
        clock.pass(11 * MINUTE);
        let places = shown_places(&shared, UID, clock.wall_ms());
        assert!(places.len() == 1 && stripped(&places[0].flow), "{places:?}");
        shared.flush();
        let written: Vec<_> = taken(&shared)
            .into_iter()
            .filter_map(|r| match r {
                crate::log::Record::Segment { flow, .. } if flow.id == 1 => Some(flow),
                _ => None,
            })
            .collect();
        assert!(
            !written.is_empty() && written.iter().all(stripped),
            "{written:?}"
        );
    }

    /// Test 16 (W10): a boot clock that cannot be read, at its largest value, overflows nothing: the end is not
    /// noted, and the sweep strips what is due.
    #[test]
    fn a_failed_boot_reading_notes_no_end_and_strips() {
        let (shared, clock, _) = telling_at(T);
        let bytes = recorded(&shared, through_proxy(1, UID, 5));
        up_at(&shared, &clock, &bytes, 500, 10);
        clock.set(T + 1_500);
        shared.tell(&on_since(T, T + 1_000, T));
        clock.fail_boot();
        shared.finish(1);
        assert!(
            lock(&shared.activity).counts.ended.is_empty(),
            "no end noted"
        );
        assert!(stripped(&shown_places(&shared, UID, T + 2_000)[0].flow));
        shared.tell(&on_since(T + 1_000, T + 2_000, T));
    }

    /// Test 17 (W7): with the switch on, nothing expires: twenty minutes after the end, the place is in full.
    #[test]
    fn with_the_switch_on_a_first_hop_never_expires() {
        let (shared, clock, _) = telling_at(T);
        shared.tunnels.set(&crate::engine::TunnelSetting {
            log_destinations: true,
            ..crate::engine::TunnelSetting::default()
        });
        let bytes = recorded(&shared, through_proxy(1, UID, 5));
        up_at(&shared, &clock, &bytes, 500, 10);
        clock.set(T + 1_500);
        shared.tell(&on_since(T, T + 1_000, T));
        shared.finish(1);
        clock.pass(20 * MINUTE);
        assert!(own_first_hop(
            &shown_places(&shared, UID, clock.wall_ms())[0].flow
        ));
        assert!(own_first_hop(&counted_places(&shared, UID)[0]));
    }

    /// Test 20 (B1): one app's flood of other destinations does not push its own proxy's first hop out: an
    /// ordinary place gives way instead, its oldest.
    #[test]
    fn one_apps_flood_does_not_push_its_first_hop_out() {
        let mut counts = Counts::default();
        let hop = through_proxy(0, UID, 5);
        counts.count(Some(UID), 1_000, [1, 0, 0, 0], BACKGROUND, Seen::Flow(&hop));
        for i in 1..=PLACES_PER_APP as u64 {
            let place = Flow {
                name: Some(format!("{i}.example")),
                ..flow(i, Some(UID))
            };
            counts.count(
                Some(UID),
                1_000 + i,
                [1, 0, 0, 0],
                BACKGROUND,
                Seen::Flow(&place),
            );
        }
        let app = &counts.apps[&Some(UID)];
        assert_eq!(app.places.len(), PLACES_PER_APP);
        assert!(
            app.places.iter().any(|p| own_first_hop(&p.flow)),
            "the first hop stays"
        );
        assert!(
            !app.places
                .iter()
                .any(|p| p.flow.name.as_deref() == Some("1.example")),
            "the oldest ordinary place went"
        );
    }

    /// Test 21 (B2): all apps' flood, 17 apps of 128 places each, does not push the first app's own proxy's first
    /// hop out past the bound of all places.
    #[test]
    fn all_apps_flood_does_not_push_a_first_hop_out() {
        let mut counts = Counts::default();
        let hop = through_proxy(0, 0, 5);
        counts.count(Some(0), 1_000, [1, 0, 0, 0], BACKGROUND, Seen::Flow(&hop));
        let mut second = 2_000;
        for uid in 0..17u32 {
            for i in u64::from(uid == 0)..PLACES_PER_APP as u64 {
                let place = Flow {
                    name: Some(format!("{i}.app{uid}.example")),
                    ..flow(i, Some(uid))
                };
                counts.count(
                    Some(uid),
                    second,
                    [1, 0, 0, 0],
                    BACKGROUND,
                    Seen::Flow(&place),
                );
                second += 1;
            }
        }
        assert_eq!(counts.places, PLACES);
        assert!(
            counts.apps[&Some(0)]
                .places
                .iter()
                .any(|p| own_first_hop(&p.flow))
        );
    }

    /// Test 22 (B3, B4): the view under construction gives first hops a cap of their own beside the app's other
    /// places: a first hop not placed yet shows beside 128 places, and of 129 first hops 128 show, the 128 others
    /// staying.
    #[test]
    fn first_hops_have_a_cap_of_their_own_in_the_view() {
        let (shared, clock, _) = telling_at(T);
        {
            let mut activity = lock(&shared.activity);
            for i in 0..PLACES_PER_APP as u64 {
                let place = Flow {
                    name: Some(format!("{i}.example")),
                    ..flow(1_000 + i, Some(UID))
                };
                activity.counts.count(
                    Some(UID),
                    T / 1000,
                    [1, 0, 0, 0],
                    BACKGROUND,
                    Seen::Flow(&place),
                );
            }
        }
        let bytes = recorded(&shared, through_proxy(1, UID, 1));
        up_at(&shared, &clock, &bytes, 500, 10);
        let places = shown_places(&shared, UID, T + 1_000);
        assert_eq!(places.len(), PLACES_PER_APP + 1);
        assert!(places.iter().any(|p| own_first_hop(&p.flow)));
        for n in 2..=u8::try_from(PLACES_PER_APP + 1).unwrap_or(u8::MAX) {
            let bytes = recorded(&shared, through_proxy(u64::from(n), UID, n));
            up_at(&shared, &clock, &bytes, 600, 10);
        }
        let places = shown_places(&shared, UID, T + 1_000);
        let hops = places.iter().filter(|p| own_first_hop(&p.flow)).count();
        assert_eq!(
            (hops, places.len() - hops),
            (PLACES_PER_APP, PLACES_PER_APP)
        );
    }

    /// Test 26 (BK): while a first hop is not kept, the next sweep sets back to its first hop whatever still holds
    /// where an app asked its proxy to go: a place made so directly, and a live flow, then `unkept`.
    #[test]
    fn the_sweep_sets_back_what_still_holds_a_destination() {
        let (shared, clock, _) = telling_at(T);
        let hop = through_proxy(1, UID, 5);
        let asked = Flow {
            name: Some("example.org".into()),
            named_by: NamedBy::Proxy,
            proxy: hop.proxy.clone().map(|p| {
                Box::new(crate::engine::Proxied {
                    asked: Some((crate::proxies::Asked::Name("example.org".into()), 443)),
                    ..*p
                })
            }),
            ..hop
        };
        lock(&shared.activity).counts.count(
            Some(UID),
            T / 1000,
            [10, 0, 0, 0],
            IN_USE,
            Seen::Flow(&asked),
        );
        let bytes = recorded(
            &shared,
            Flow {
                id: 2,
                ..asked.clone()
            },
        );
        up_at(&shared, &clock, &bytes, 500, 10);
        let places = shown_places(&shared, UID, T + 1_000);
        assert!(
            places.len() == 1
                && !holds_destination(&places[0].flow)
                && places[0].flow.name.as_deref() == Some("proxy-5.example.net"),
            "{places:?}"
        );
        let live = lock(&shared.live);
        assert!(!holds_destination(&live[&2].flow) && live[&2].unkept);
    }

    /// Test 27 (P1): clearing the live view, as ADR 0047's profile does at each screen-off, forgets every first hop
    /// shown in full, their organisations and the table of ends; a held segment's seconds from before the clear
    /// stay out; an open flow's next bytes show its first hop again, as this screen-on's.
    #[test]
    fn clearing_the_live_view_forgets_every_full_first_hop() {
        let (shared, clock, _) = telling_at(T);
        let ended = recorded(&shared, through_proxy(1, UID, 5));
        let open = recorded(&shared, through_proxy(2, UID, 6));
        let held = recorded(&shared, through_proxy(3, UID, 7));
        up_at(&shared, &clock, &ended, 500, 10);
        up_at(&shared, &clock, &open, 500, 10);
        clock.set(T + 1_500);
        shared.tell(&on_since(T, T + 1_000, T));
        up_at(&shared, &clock, &held, 1_600, 30);
        shared.finish(1);
        shared.finish(3);
        assert_eq!(shown_places(&shared, UID, T + 2_000).len(), 3);
        {
            let activity = lock(&shared.activity);
            assert!(!activity.counts.ended.is_empty() && !activity.counts.organisations.is_empty());
        }
        lock(&shared.activity).counts.clear(T + 2_000);
        {
            let activity = lock(&shared.activity);
            assert!(activity.counts.ended.is_empty(), "no end");
            assert!(activity.counts.organisations.is_empty(), "no organisation");
            assert!(activity.counts.places_of(Some(UID)).is_empty(), "no place");
        }
        let snapshot = shared.now_view(T + 2_000);
        assert!(snapshot.apps.is_empty(), "{:?}", snapshot.apps);
        let encoded = crate::snapshot::encode(&snapshot);
        for n in [5, 6, 7] {
            assert!(!encoded.windows(4).any(|w| w == [203, 0, 113, n]), "{n}");
        }
        up_at(&shared, &clock, &open, 2_500, 40);
        let places = shown_places(&shared, UID, T + 3_000);
        assert!(
            places.len() == 1
                && places[0].flow.destination == SocketAddr::from(([203, 0, 113, 6], 1080))
                && own_first_hop(&places[0].flow),
            "{places:?}"
        );
    }
}
