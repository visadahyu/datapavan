//! The network part's own cache of the network resolver's answers, for the apps that go directly while a chain is
//! on (ADR 0038). Then every answer reaches the apps with a time to live of 0, so that Android's shared
//! cache keeps none; without a cache of its own, the network part would send the network's resolver a query for
//! every lookup, many more than before. This cache keeps each answer for the time to live it came with
//! and answers the same question from it, so that the network sees no more queries than without a chain.
//!
//! It holds answers ("no error", and "no such name" with an SOA record) to one question, never a
//! truncated one, at most [`CAPACITY`] of them, the oldest going first. It lives in memory only.
//!
//! Its time is the time since the phone started, its sleep included (`CLOCK_BOOTTIME`, the engine's
//! `Clock::since_boot`): an answer whose time to live runs out while the phone sleeps is gone when it
//! wakes, as from Android's own resolver, and a wall clock set back or forward changes nothing. On the
//! monotonic clock, which stands still in a sleep, an answer of five minutes cached before a night was
//! served the next morning (finding 4 of the independent review of 2026-11-09).

use crate::answers;
use crate::dns::{ttl_offsets, u16_at, u32_at};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;

/// The most answers kept.
pub const CAPACITY: usize = 4096;
/// The longest an answer is kept, however long its time to live: as Android's own resolver bounds it.
pub const MAX_KEEP: Duration = Duration::from_hours(24);
const TYPE_SOA: u16 = 6;

/// A question: its name in lower case, type and class.
type Key = (String, u16, u16);

/// Answers by question, each with the time since the phone started until which it is kept.
#[derive(Debug, Default)]
pub struct DnsCache {
    entries: HashMap<Key, (Vec<u8>, Duration)>,
    order: VecDeque<Key>,
    /// How long past its time an answer is still kept to be served stale (RFC 8767); none by default.
    stale_for: Duration,
}

/// The time to live of an answer served stale (RFC 8767, 4: "30 seconds").
pub const STALE_TTL: u32 = 30;

impl DnsCache {
    /// A cache that keeps each answer `stale_for` past its time to live, for [`DnsCache::stale`].
    #[must_use]
    pub fn serving_stale(stale_for: Duration) -> Self {
        Self {
            stale_for,
            ..Self::default()
        }
    }

    /// The answer kept for `query`'s question whose time ran out by `now` less than the stale window ago,
    /// with every record's time to live [`STALE_TTL`], the query's ID and question: served while a fresh
    /// answer is asked for (RFC 8767). `None` for a fresh answer ([`DnsCache::answer`] gives it), none kept,
    /// or one past the window, which is forgotten.
    pub fn stale(&mut self, query: &[u8], now: Duration) -> Option<Vec<u8>> {
        let question = answers::question(query)?;
        let key = (question.name, question.kind, question.class);
        let (_, until) = self.entries.get(&key)?;
        if *until > now {
            return None;
        }
        if until.saturating_add(self.stale_for) <= now {
            self.entries.remove(&key);
            self.order.retain(|k| k != &key);
            return None;
        }
        let mut out = self.entries.get(&key)?.0.clone();
        for at in ttl_offsets(&out)? {
            out.get_mut(at..at + 4)?
                .copy_from_slice(&STALE_TTL.to_be_bytes());
        }
        out.get_mut(..2)?.copy_from_slice(query.get(..2)?);
        Some(out)
    }

    /// Keeps `answer` for its shortest time to live (for "no such name", the SOA record's, bounded by
    /// its minimum field, RFC 2308), if it is one to keep. `now` is the time since the phone started; the
    /// longest time there is, as a failed reading gives, keeps nothing, since a later reading that works
    /// would find the answer kept for ever.
    pub fn insert(&mut self, answer: &[u8], now: Duration) {
        if now == Duration::MAX {
            return;
        }
        let Some((key, keep)) = keepable(answer) else {
            return;
        };
        if self
            .entries
            .insert(key.clone(), (answer.to_vec(), now.saturating_add(keep)))
            .is_none()
        {
            self.order.push_back(key);
        }
        while self.order.len() > CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }

    /// The answer kept for `query`'s question, if it has not run out by `now`, the time since the phone
    /// started: with the query's ID, and its question as the query wrote it.
    pub fn answer(&mut self, query: &[u8], now: Duration) -> Option<Vec<u8>> {
        let question = answers::question(query)?;
        let key = (question.name, question.kind, question.class);
        let (kept, until) = self.entries.get(&key)?;
        if *until <= now {
            // Kept for its stale window, if it has one.
            if until.saturating_add(self.stale_for) <= now {
                self.entries.remove(&key);
                self.order.retain(|k| k != &key);
            }
            return None;
        }
        let mut out = kept.clone();
        out.get_mut(..2)?.copy_from_slice(query.get(..2)?);
        // Same name, so the same length; the letters' case is the query's.
        let end = question_end(query)?;
        if question_end(&out)? == end {
            out.get_mut(12..end)?.copy_from_slice(query.get(12..end)?);
        }
        Some(out)
    }

    /// How many answers are kept.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether none is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Forgets every answer, as when the network beneath or the chain changes.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }
}

/// Where the one question of a message ends.
fn question_end(message: &[u8]) -> Option<usize> {
    let mut at = 12;
    loop {
        let length = *message.get(at)?;
        match length >> 6 {
            0 if length == 0 => return Some(at + 1 + 4),
            0 => at += 1 + usize::from(length),
            _ => return None,
        }
    }
}

/// The question an answer is for, and how long to keep it; `None` for an answer not to keep.
fn keepable(answer: &[u8]) -> Option<(Key, Duration)> {
    let flags = u16_at(answer, 2)?;
    // A response, not truncated, "no error" (0) or "no such name" (3).
    if flags & 0x8000 == 0 || flags & 0x0200 != 0 || !matches!(flags & 0x000f, 0 | 3) {
        return None;
    }
    // The question, read as a query's.
    let mut query = answer.get(..question_end(answer)?)?.to_vec();
    query[2] &= 0x7f;
    query[4..12].copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    let question = answers::question(&query)?;
    let mut shortest: Option<u32> = None;
    for at in ttl_offsets(answer)? {
        let mut ttl = u32_at(answer, at)?;
        if u16_at(answer, at - 4)? == TYPE_SOA {
            let length = usize::from(u16_at(answer, at + 4)?);
            ttl = ttl.min(u32_at(answer, at + 6 + length - 4)?);
        }
        shortest = Some(shortest.map_or(ttl, |s| s.min(ttl)));
    }
    // An answer with no record at all says nothing about how long it holds.
    let ttl = shortest.filter(|&t| t > 0)?;
    let keep = Duration::from_secs(u64::from(ttl)).min(MAX_KEEP);
    Some(((question.name, question.kind, question.class), keep))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u8, name: &[u8]) -> Vec<u8> {
        let mut q = vec![id, id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(name);
        q.extend_from_slice(&[0, 1, 0, 1]);
        q
    }

    /// An answer to `query` with one A record of `ttl` seconds.
    fn answer(query: &[u8], ttl: u32) -> Vec<u8> {
        let mut a = query.to_vec();
        a[2] = 0x81;
        a[3] = 0x80;
        a[7] = 1;
        a.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        a.extend_from_slice(&ttl.to_be_bytes());
        a.extend_from_slice(&[0, 4, 93, 184, 216, 34]);
        a
    }

    /// An hour after the phone started.
    const NOW: Duration = Duration::from_hours(1);

    #[test]
    fn a_stale_answer_is_served_with_30_seconds_within_its_window_only() {
        let mut cache = DnsCache::serving_stale(Duration::from_hours(24));
        let first = query(1, b"\x07example\x03com\x00");
        cache.insert(&answer(&first, 300), NOW);
        let again = query(2, b"\x07example\x03com\x00");
        assert!(cache.stale(&again, NOW).is_none(), "fresh: not stale");
        let later = NOW + Duration::from_secs(301);
        assert!(cache.answer(&again, later).is_none());
        let Some(stale) = cache.stale(&again, later) else {
            unreachable!("served stale")
        };
        assert_eq!(stale[..2], [2, 2]);
        assert_eq!(u32_at(&stale, stale.len() - 10), Some(STALE_TTL));
        assert!(
            cache
                .stale(
                    &again,
                    NOW + Duration::from_secs(300) + Duration::from_hours(24)
                )
                .is_none(),
            "past the window"
        );
        assert!(cache.is_empty(), "and forgotten");
        let mut plain = DnsCache::default();
        plain.insert(&answer(&first, 300), NOW);
        assert!(
            plain.stale(&again, later).is_none(),
            "no window, no stale answer"
        );
    }

    #[test]
    fn answers_the_same_question_until_its_time_to_live_runs_out() {
        let mut cache = DnsCache::default();
        let now = NOW;
        let first = query(1, b"\x07example\x03com\x00");
        cache.insert(&answer(&first, 300), now);
        assert_eq!(cache.len(), 1);
        let again = query(2, b"\x07EXAMPLE\x03com\x00");
        let Some(out) = cache.answer(&again, now + Duration::from_secs(299)) else {
            unreachable!("kept")
        };
        assert_eq!(out[..2], [2, 2], "the query's ID");
        assert_eq!(out[12..again.len()], again[12..], "the query's question");
        assert_eq!(out[again.len()..], answer(&first, 300)[first.len()..]);
        assert_eq!(cache.answer(&again, now + Duration::from_secs(300)), None);
        assert!(cache.is_empty(), "run out, it goes");
        assert_eq!(
            cache.answer(&query(3, b"\x07example\x03org\x00"), now),
            None
        );
    }

    /// Kept before a night's sleep for five minutes, an answer is gone in the morning, though the phone
    /// was awake for less; and the time since start never ends a cache.
    #[test]
    fn an_answer_whose_time_to_live_ran_out_in_a_sleep_is_gone() {
        let mut cache = DnsCache::default();
        let q = query(1, b"\x07example\x03com\x00");
        cache.insert(&answer(&q, 300), NOW);
        assert!(cache.answer(&q, NOW + Duration::from_mins(4)).is_some());
        assert_eq!(cache.answer(&q, NOW + Duration::from_hours(8)), None);
        // A failed reading of the clock keeps nothing, also once readings work again.
        let mut cache = DnsCache::default();
        cache.insert(&answer(&q, 300), Duration::MAX);
        assert!(cache.is_empty());
        assert_eq!(cache.answer(&q, NOW), None);
    }

    #[test]
    fn keeps_no_answer_without_a_time_to_live_and_no_failure() {
        let mut cache = DnsCache::default();
        let now = NOW;
        let q = query(1, b"\x07example\x03com\x00");
        cache.insert(&answer(&q, 0), now);
        let mut failed = answer(&q, 300);
        failed[3] = 0x82;
        cache.insert(&failed, now);
        let mut cut = answer(&q, 300);
        cut[2] |= 0x02;
        cache.insert(&cut, now);
        let mut empty = q.clone();
        empty[2] = 0x81;
        empty[3] = 0x80;
        cache.insert(&empty, now);
        cache.insert(&q, now);
        assert!(cache.is_empty());
    }

    #[test]
    fn keeps_no_such_name_for_the_soa_minimum() {
        let mut cache = DnsCache::default();
        let now = NOW;
        let q = query(1, b"\x04nope\x07example\x03com\x00");
        let mut a = q.clone();
        a[2] = 0x81;
        a[3] = 0x83;
        a[9] = 1;
        // An SOA record of 3600 s whose minimum field is 60 s.
        let mut data = b"\x02ns\xc0\x11\x05admin\xc0\x11".to_vec();
        data.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 60]);
        a.extend_from_slice(&[0xc0, 0x11, 0, 6, 0, 1, 0, 0, 0x0e, 0x10]);
        a.extend_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_be_bytes());
        a.extend_from_slice(&data);
        cache.insert(&a, now);
        assert!(cache.answer(&q, now + Duration::from_secs(59)).is_some());
        assert_eq!(cache.answer(&q, now + Duration::from_secs(60)), None);
    }

    #[test]
    fn holds_at_most_its_capacity() {
        let mut cache = DnsCache::default();
        let now = NOW;
        for i in 0..=CAPACITY {
            let name = format!("n{i}");
            let mut wire = vec![u8::try_from(name.len()).unwrap_or(0)];
            wire.extend_from_slice(name.as_bytes());
            wire.push(0);
            cache.insert(&answer(&query(1, &wire), 300), now);
        }
        assert_eq!(cache.len(), CAPACITY);
        assert_eq!(
            cache.answer(&query(1, b"\x02n0\x00"), now),
            None,
            "the oldest went"
        );
    }
}
