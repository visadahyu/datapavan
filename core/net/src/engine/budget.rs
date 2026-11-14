//! The engine's budget (ADR 0044, decision 3): what it holds for the apps is capped for every app
//! together, by what the process may open, and shared out among them, so that one app that misbehaves
//! cannot use up what every other app needs. Each app may hold a share of the cap; the flows whose app
//! Android cannot name are one app here, and share one share. So four apps must use their whole share
//! before the cap touches any other.

use super::lock;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Places, held for every app together and for each, against a cap and a share. Its lock is only ever
/// taken last: nothing else is locked while it is held.
pub(super) struct Budget {
    cap: usize,
    share: usize,
    held: Mutex<Held>,
}

/// How many places are held, in all and by each app.
#[derive(Default)]
struct Held {
    all: usize,
    by_app: HashMap<Option<u32>, usize>,
}

/// Why no place could be had.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Full {
    /// The app holds its whole share.
    App,
    /// Every app together holds the whole cap.
    All,
}

/// One place, held by the app `uid` until it is dropped.
pub(super) struct Place {
    budget: Arc<Budget>,
    uid: Option<u32>,
}

impl Budget {
    /// A budget of `cap` places, of which each app may hold `share`.
    pub(super) fn new(cap: usize, share: usize) -> Arc<Self> {
        Arc::new(Self {
            cap,
            share,
            held: Mutex::default(),
        })
    }

    /// A place for the app `uid`, if it holds less than its share and every app together less than the
    /// cap. The share is asked first: an app at its share makes room among its own, wherever the cap
    /// stands.
    pub(super) fn take(self: &Arc<Self>, uid: Option<u32>) -> Result<Place, Full> {
        let mut held = lock(&self.held);
        if held.by_app.get(&uid).copied().unwrap_or(0) >= self.share {
            return Err(Full::App);
        }
        if held.all >= self.cap {
            return Err(Full::All);
        }
        held.all += 1;
        *held.by_app.entry(uid).or_default() += 1;
        Ok(Place {
            budget: Arc::clone(self),
            uid,
        })
    }

    /// A place for the app `uid` whatever it and every app hold: for what has already left the phone,
    /// which must not be dropped unlogged. It counts as any other, so that the app's next places see it.
    pub(super) fn force(self: &Arc<Self>, uid: Option<u32>) -> Place {
        let mut held = lock(&self.held);
        held.all += 1;
        *held.by_app.entry(uid).or_default() += 1;
        Place {
            budget: Arc::clone(self),
            uid,
        }
    }

    /// How many places the app `uid` holds, and every app together.
    #[cfg(test)]
    pub(super) fn held(&self, uid: Option<u32>) -> (usize, usize) {
        let held = lock(&self.held);
        (held.by_app.get(&uid).copied().unwrap_or(0), held.all)
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let mut held = lock(&self.budget.held);
        held.all = held.all.saturating_sub(1);
        if let Some(count) = held.by_app.get_mut(&self.uid) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                held.by_app.remove(&self.uid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: Option<u32> = Some(10_100);
    const TWO: Option<u32> = Some(10_200);

    /// An app gets places up to its share, and every app together up to the cap; a place dropped is
    /// had again, by the app that held it or by another.
    #[test]
    fn places_are_had_up_to_the_share_and_the_cap() {
        let budget = Budget::new(3, 2);
        let first = budget.take(ONE).ok();
        let second = budget.take(ONE).ok();
        assert!(first.is_some() && second.is_some());
        assert_eq!(budget.take(ONE).err(), Some(Full::App));
        let third = budget.take(TWO).ok();
        assert!(third.is_some());
        assert_eq!(budget.take(TWO).err(), Some(Full::All));
        assert_eq!(budget.take(None).err(), Some(Full::All));
        assert_eq!(budget.held(ONE), (2, 3));
        drop(first);
        assert_eq!(budget.held(ONE), (1, 2));
        assert!(budget.take(TWO).is_ok(), "the place ONE gave back");
        assert_eq!(budget.held(TWO), (1, 2), "given back as it was dropped");
    }

    /// A place forced on an app beyond its share counts as any other.
    #[test]
    fn a_forced_place_counts_as_any_other() {
        let budget = Budget::new(2, 1);
        let held = budget.take(ONE).ok();
        assert!(held.is_some());
        let forced = budget.force(ONE);
        assert_eq!(budget.held(ONE), (2, 2));
        assert_eq!(budget.take(TWO).err(), Some(Full::All));
        drop(forced);
        assert_eq!(budget.held(ONE), (1, 1));
    }

    /// The flows whose app Android cannot name share one share.
    #[test]
    fn unknown_apps_share_one_share() {
        let budget = Budget::new(10, 2);
        let held = [budget.take(None).ok(), budget.take(None).ok()];
        assert!(held.iter().all(Option::is_some));
        assert_eq!(budget.take(None).err(), Some(Full::App));
        assert!(budget.take(ONE).is_ok());
    }
}
