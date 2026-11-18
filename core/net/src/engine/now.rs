//! The live counters behind "Now" (ADR 0046, decision 2 (d)): each placed second's bytes, as the app sent
//! and received them, go to its app's counts by state, in whole minutes over the last hour and since
//! the screen last came on, and to the destination its flow reached, named as W3 names it. A chained
//! app's flow whose destination stays out of the log adds to its app's counts only, with the mark that it
//! went through the user's tool ("Log where these apps connect" off). Lookups to Watch's own DNS address
//! are the log's only.
//!
//! All of it is memory only, written to no file, kept with retention "none" too, handed to the next
//! engine when the tunnel is set up again, and gone when Watch stops. It is bounded: at most [`APPS`]
//! apps, each with at most 61 minutes of counts, and [`PLACES`] destinations for all apps together and
//! [`PLACES_PER_APP`] for one, each with at most 61 minutes of counts and names of at most 253 bytes;
//! past a bound, the app or destination with bytes the longest ago gives way (ADR 0046's "How it is
//! built" gives the bytes).
//!
//! The seconds not placed yet count in the snapshot in a column of their own, "not told yet", from the
//! flows' and the held segments' marks, so that the view needs no reading to show them.

use super::activity::{Mark, Of};
use super::{Flow, NamedBy, Network, Shared, lock};
use crate::snapshot::{AppNow, PlaceNow, Snapshot, Ways};
use crate::states::Placed;
use std::collections::{BTreeMap, HashMap, VecDeque};

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

/// Bytes up and down by column: no state, in use, with its notification, in the background.
type ByState = [Ways; 4];

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
    HiddenDirect,
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
            (true, false) => Self::Hidden,
            (true, true) => Self::HiddenDirect,
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
/// from, the DNS name beside it and the app's own DNS; and by address where neither has a name.
fn same_place(a: &Flow, b: &Flow) -> bool {
    a.name == b.name
        && a.named_by == b.named_by
        && a.dns_name == b.dns_name
        && a.dns == b.dns
        && (a.name.is_some() || a.destination.ip() == b.destination.ip())
}

/// One app's counts.
#[derive(Default)]
struct App {
    minutes: Minutes<ByState>,
    session: ByState,
    /// The last second a flow of it went through the user's tool with its destination left out.
    through_tool: Option<u64>,
    /// The last second it sent or received.
    last: u64,
    places: Vec<Place>,
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
}

impl Counts {
    /// The screen came on at `since`: the window since it did begins anew.
    pub(super) fn screen_on(&mut self, since: u64) {
        if self.session == Some(since) {
            return;
        }
        self.session = Some(since);
        for app in self.apps.values_mut() {
            app.session = ByState::default();
            for place in &mut app.places {
                place.session = Ways::default();
            }
        }
    }

    /// The wall clock was set back to `now`: the minutes later than its own are of the old clock, and so
    /// is the moment the screen came on if it is later too; both are forgotten, so that the windows hold
    /// the new clock's bytes (review b1 of W5's second part, engine, finding 5).
    pub(super) fn set_back(&mut self, now: u64) {
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
        if self.session.is_some_and(|since| since > now) {
            self.session = None;
            for app in self.apps.values_mut() {
                app.session = ByState::default();
                for place in &mut app.places {
                    place.session = Ways::default();
                }
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
                self.places -= app.places.len();
                app.places.clear();
                if let Some(last) = routed {
                    app.through_tool = Some(app.through_tool.map_or(last, |s| s.max(last)));
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
        if (up == 0 && down == 0) || matches!(seen, Seen::Lookups) {
            return;
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
        let column = placed.column();
        let minute = second / 60;
        let app = self.apps.entry(uid).or_default();
        add_minute(&mut app.minutes, minute, |counts: &mut ByState| {
            counts[column][0] += up;
            counts[column][1] += down;
        });
        if in_session {
            app.session[column][0] += up;
            app.session[column][1] += down;
        }
        app.last = app.last.max(second);
        let (flow, routed) = match seen {
            Seen::Flow(flow) => (flow, false),
            Seen::Routed(flow) => (flow, true),
            Seen::Hidden => {
                app.through_tool = Some(app.through_tool.map_or(second, |s| s.max(second)));
                return;
            }
            Seen::HiddenDirect | Seen::Lookups => return,
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

    /// Forgets the destination, of any app, with bytes the longest ago.
    fn forget_oldest_place(&mut self) {
        let oldest = self
            .apps
            .iter()
            .filter_map(|(uid, app)| {
                oldest_place(&app.places).map(|at| (app.places[at].last, *uid, at))
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

/// Where the destination with bytes the longest ago is in `places`.
fn oldest_place(places: &[Place]) -> Option<usize> {
    places
        .iter()
        .enumerate()
        .min_by_key(|(_, place)| place.last)
        .map(|(at, _)| at)
}

impl Shared {
    /// What the live view "Now" draws at the wall clock's `now`: each app's bytes by state in each
    /// window, the seconds not placed yet in a column apart, and its destinations with theirs.
    pub(super) fn now_view(&self, now: u64) -> Snapshot {
        let tool = self.chain().map(|chain| chain.tool);
        let (view, head, mut found) = {
            let live = lock(&self.live);
            let mut activity = lock(&self.activity);
            activity.counts.forget_old(now);
            let mut view = View::new(now, activity.counts.session);
            for (&uid, app) in &activity.counts.apps {
                view.settled(uid, app);
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
        self.look_up(&view, &mut found);
        let (known, told_until, screen, session, states) = head;
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
    /// named it, else the table's for its address, if Watch has the table.
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
    apps: BTreeMap<Option<u32>, AppView>,
}

#[derive(Default)]
struct AppView {
    /// By window (10 minutes, an hour, since the screen came on), then by column (no state, in use,
    /// with its notification, in the background, not told yet).
    bytes: [[Ways; 5]; 3],
    through_tool: bool,
    places: Vec<(Flow, [Ways; 3])>,
}

impl View {
    fn new(now: u64, session: Option<u64>) -> Self {
        let minute = now / 60_000;
        Self {
            firsts: WINDOWS.map(|w| minute.saturating_sub(w - 1)),
            session,
            apps: BTreeMap::new(),
        }
    }

    /// The windows a second falls in: the 10 minutes, the hour, since the screen came on.
    fn windows(&self, second: u64) -> [bool; 3] {
        let minute = second / 60;
        [
            minute >= self.firsts[0],
            minute >= self.firsts[1],
            self.session
                .is_some_and(|since| second.saturating_mul(1000) >= since),
        ]
    }

    /// An app's counts placed.
    fn settled(&mut self, uid: Option<u32>, app: &App) {
        let mut view = AppView {
            through_tool: app
                .through_tool
                .is_some_and(|second| self.windows(second).iter().any(|&w| w)),
            ..AppView::default()
        };
        for (minute, counts) in &app.minutes {
            let windows = self.windows(minute * 60);
            for (w, inside) in windows.into_iter().take(2).enumerate() {
                if inside {
                    add_columns(&mut view.bytes[w], counts);
                }
            }
        }
        add_columns(&mut view.bytes[2], &app.session);
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
                view.places.push((place.flow.clone(), bytes));
            }
        }
        if view.bytes != [[Ways::default(); 5]; 3] || view.through_tool {
            self.apps.insert(uid, view);
        }
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
            if ways == Ways::default() {
                continue;
            }
            let windows = self.windows(mark.second);
            let app = self.apps.entry(uid).or_default();
            for (w, inside) in windows.into_iter().enumerate() {
                if inside {
                    add(&mut app.bytes[w][4], ways);
                }
            }
            let flow = match seen {
                Seen::Hidden => {
                    app.through_tool = true;
                    continue;
                }
                Seen::Flow(flow) | Seen::Routed(flow) => flow,
                Seen::HiddenDirect | Seen::Lookups => continue,
            };
            // The flow's destination, found once for all its marks (review b1, engine, nit 3).
            let at = *place.get_or_insert_with(|| {
                app.places
                    .iter()
                    .position(|(f, _)| same_place(f, flow))
                    .or_else(|| {
                        (app.places.len() < PLACES_PER_APP).then(|| {
                            app.places.push((flow.clone(), [Ways::default(); 3]));
                            app.places.len() - 1
                        })
                    })
            });
            let Some(at) = at else {
                continue;
            };
            for (w, inside) in windows.into_iter().enumerate() {
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

fn add_columns(to: &mut [Ways; 5], more: &ByState) {
    for (column, ways) in more.iter().enumerate() {
        add(&mut to[column], *ways);
    }
}

#[cfg(test)]
mod tests {
    use super::super::activity::tests::{
        BACKGROUND, IN_USE, NOTIFICATION, T, Telling, UID, flow, open, telling_at, told, up_at,
    };
    use super::super::tests::shared_with;
    use super::*;
    use crate::states::{Interval, Known, State, Told};
    use std::net::SocketAddr;
    use std::sync::Arc;

    const MINUTE: u64 = 60_000;

    /// The bytes of `uid` in `snapshot`, by window and column.
    fn bytes_of(snapshot: &Snapshot, uid: Option<u32>) -> [[Ways; 5]; 3] {
        snapshot
            .apps
            .iter()
            .find(|app| app.uid == uid)
            .map_or([[[0; 2]; 5]; 3], |app| app.bytes)
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
        assert_eq!(bytes_of(&snapshot, Some(UID))[2], [[0; 2]; 5]);
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
        let tool = app_of(&snapshot, Some(10_200)).map(|a| (a.tool, a.places.len()));
        assert_eq!(tool, Some((true, 1)));
        assert_eq!(lock(&shared.activity).counts.places, 4);
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

    /// Where the fixture Watch's Kotlin side reads is kept (`SnapshotTest`).
    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../android/watch/src/test/resources/org/visadahyu/datapavan/watch/activity/snapshot.hex"
    );

    /// The fixture Watch's Kotlin side reads is what the engine writes, byte for byte, as for the log
    /// (`logbook`): from an engine's own counts, of an app placed in each state, a chained app, the tool
    /// and flows of no app, read with no usage access at the end.
    #[test]
    fn the_kotlin_sides_snapshot_fixture_is_what_the_engine_writes() -> std::io::Result<()> {
        let platform = Arc::new(Telling::default());
        let clock = super::super::clock::ManualClock::at(T);
        let mut shared = shared_with(platform);
        shared.clock = clock.clone();
        let bytes = open(&shared, 1);
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
            intervals: Vec::new(),
        });
        let snapshot = shared.now_view(T + 4_000);
        let all = bytes_of(&snapshot, Some(UID));
        assert_eq!(
            (all[0][1], all[0][2], all[0][3], all[0][4]),
            ([100, 0], [200, 0], [300, 0], [400, 1_000])
        );
        assert_eq!(all[2][1], [0, 0], "before the screen came on");
        assert_eq!(bytes_of(&snapshot, None)[0][0], [50, 0]);
        let mut text = String::from(
            "# Watch's live view: one snapshot as the engine writes it (core/net/src/snapshot.rs, version 1), in\n\
             # hex. Written by the engine's test the_kotlin_sides_snapshot_fixture_is_what_the_engine_writes\n\
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
}
