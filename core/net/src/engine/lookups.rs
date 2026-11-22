//! The lookups of chained apps (ADR 0038): the network part answers A, AAAA and reverse lookups of stand-ins
//! itself, and every other question goes through the tool: by the encrypted ways of the network part's resolver once it
//! is set (W8, part 1), else to Quad9's service without blocking, as DNS over TCP on a connection the network part
//! keeps ([`super::kept`]); so that no lookup of a chained app reaches the network beneath.

use super::chain::Chain;
use super::{Shared, kept, lock, resolver};
use crate::answers::{self, A, AAAA};
use crate::hygiene;
use crate::standins::is_stand_in;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Quad9's service without blocking, `quad9-unsecured` in `data/resolvers`: the resolver of chained
/// apps' other questions until the user chooses one (ADR 0038, decided by the maintainer).
pub(super) const RESOLVERS: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 10)), 53),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(149, 112, 112, 10)), 53),
];

/// How long a question through the tool may take, for each resolver address in turn. Android's
/// resolver gives up on a lookup after about five seconds and asks again.
pub(super) const LOOKUP_TIMEOUT: Duration = Duration::from_secs(4);

/// The answer to a chained app's `query`, of the app `uid` if Android named it, or `None` when it is not even a
/// DNS message with an ID. A question tracker blocking stops for the app gets "no data" kept for no time before
/// any stand-in is given or anything goes to the tool (W8, part 3a; ADR 0053): the network part never resolves a
/// chained app's names, so the question's name is all it matches (ADR 0038).
pub(super) async fn answer(
    shared: &Arc<Shared>,
    chain: &Arc<Chain>,
    query: &[u8],
    uid: Option<u32>,
) -> Option<Vec<u8>> {
    let Some(question) = answers::question(query) else {
        return answers::failure(query);
    };
    if let Some(blocked) = shared.lookup_blocked(uid, query) {
        return Some(blocked);
    }
    if answers::answered_here(&question) {
        match question.kind {
            A => {
                let address = lock(&shared.stand_ins).address(&question.name);
                return answers::address(query, &question, address);
            }
            AAAA => return answers::no_data(query, &question),
            _ => {
                if let Some(stand_in) =
                    answers::reverse_v4(&question.name).filter(|a| is_stand_in(IpAddr::V4(*a)))
                {
                    let name = lock(&shared.stand_ins).name(IpAddr::V4(stand_in));
                    return match name {
                        Some(name) => answers::name(query, &question, &name),
                        None => answers::no_data(query, &question),
                    };
                }
            }
        }
    }
    // Asked before: the answer the network part keeps for the tool's route, for its time to live, so that each name
    // costs one trip through the tool, not one per lookup (ADR 0038).
    let kept = lock(&shared.tool_answers).answer(query, shared.clock.since_boot());
    if let Some(kept) = kept {
        return answers::rebuilt(&kept).or_else(|| answers::failure(query));
    }
    // Once the network part's encrypted resolver is set (W8, part 1), these questions go the encrypted ways through the
    // tool, never to Quad9 in plain DNS (ADR 0038 gave this path to W8).
    if shared.resolver.on() {
        let Some(asked) = hygiene::read(query) else {
            return answers::failure(query);
        };
        let answer = resolver::through_tool(shared, chain, &asked)
            .await
            .and_then(|upstream| asked.answer(&upstream, None));
        return match answer {
            Some(answer) => {
                lock(&shared.tool_answers).insert(&answer, shared.clock.since_boot());
                answers::rebuilt(&answer).or_else(|| answers::failure(query))
            }
            None => answers::failure(query),
        };
    }
    match through_tool(shared, chain, query).await {
        Ok(answer) => {
            lock(&shared.tool_answers).insert(&answer, shared.clock.since_boot());
            answers::rebuilt(&answer).or_else(|| answers::failure(query))
        }
        Err(_) => answers::failure(query),
    }
}

/// Asks the resolvers in turn, through the tool.
async fn through_tool(
    shared: &Arc<Shared>,
    chain: &Arc<Chain>,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let mut last = io::Error::from(io::ErrorKind::HostUnreachable);
    for resolver in RESOLVERS {
        match tokio::time::timeout(LOOKUP_TIMEOUT, kept::ask(shared, chain, resolver, query)).await
        {
            Ok(Ok(answer)) => return Ok(answer),
            Ok(Err(error)) => last = error,
            Err(_) => last = io::ErrorKind::TimedOut.into(),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::super::tests::shared;
    use super::*;
    use crate::dns;
    use crate::resolvers::Resolvers;

    fn chain() -> Arc<Chain> {
        // No proxy listens on this port: questions that need the tool fail.
        Arc::new(Chain {
            proxy: SocketAddr::from(([127, 0, 0, 1], 9)),
            credentials: None,
            tool: 10_200,
            apps: None,
            udp: true,
            log_destinations: false,
        })
    }

    fn query(name: &[u8], kind: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(name);
        q.extend_from_slice(&kind.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    #[test]
    fn the_resolvers_are_quad9_without_blocking() {
        let table = Resolvers::bundled();
        for resolver in RESOLVERS {
            assert_eq!(table.at(resolver.ip()), Some("quad9-unsecured"));
        }
    }

    /// A chained app's question tracker blocking stops gets "no data" kept for no time before any stand-in is given
    /// (W8, part 3a; ADR 0053), so its name never reaches the tool; another app's gets its stand-in, and a stand-in
    /// for the name connected to anyway is refused before the tool is asked (`tcp::blocked_before`).
    #[tokio::test(flavor = "current_thread")]
    async fn a_chained_apps_blocked_question_gets_no_stand_in() {
        let shared = Arc::new(shared());
        shared.set_blocking(super::super::BlockSetting {
            on: true,
            table: Some(Arc::new(crate::blocking::tests::table(&[(
                "tracker.example",
                "block",
            )]))),
            covered: vec![10_123],
            ..super::super::BlockSetting::default()
        });
        let chain = chain();
        let a = query(b"\x07tracker\x07example\x00", A);
        let Some(blocked) = answer(&shared, &chain, &a, Some(10_123)).await else {
            unreachable!("an answer")
        };
        assert_eq!(blocked[6..10], [0, 0, 0, 1], "no answer, an SOA");
        assert_eq!(
            lock(&shared.stand_ins).name(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))),
            None
        );
        let Some(other) = answer(&shared, &chain, &a, Some(10_124)).await else {
            unreachable!("an answer")
        };
        let Some(read) = dns::response(&other) else {
            unreachable!("a response")
        };
        let stand_in = read.addresses.first().map(|(ip, _)| *ip);
        assert!(stand_in.is_some_and(is_stand_in));
        let to = SocketAddr::new(stand_in.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 443);
        assert!(super::super::tcp::blocked_before(&shared, Some(10_123), to).is_some());
        assert_eq!(
            super::super::tcp::blocked_before(&shared, Some(10_124), to),
            None
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn answers_a_aaaa_and_reverse_lookups_here() {
        let shared = Arc::new(shared());
        let chain = chain();
        let a = query(b"\x07example\x03com\x00", A);
        let Some(answer) = answer(&shared, &chain, &a, None).await else {
            unreachable!("an answer")
        };
        let Some(read) = dns::response(&answer) else {
            unreachable!("a response")
        };
        assert_eq!(
            read.addresses,
            vec![(Ipv4Addr::new(198, 18, 0, 1).into(), 0)]
        );
        let Some(again) = super::answer(&shared, &chain, &a, None).await else {
            unreachable!("an answer")
        };
        assert_eq!(again, answer, "the same stand-in");
        let Some(empty) = super::answer(
            &shared,
            &chain,
            &query(b"\x07example\x03com\x00", AAAA),
            None,
        )
        .await
        else {
            unreachable!("an answer")
        };
        assert_eq!(empty[6..8], [0, 0]);
        let ptr = query(
            b"\x011\x010\x0218\x03198\x07in-addr\x04arpa\x00",
            answers::TYPE_PTR,
        );
        let Some(reverse) = super::answer(&shared, &chain, &ptr, None).await else {
            unreachable!("an answer")
        };
        assert!(reverse.ends_with(b"\x07example\x03com\x00"));
    }

    /// An answer kept for a chained app is kept for its time to live in time since the phone started,
    /// its sleep included (finding 4): it answers the question until then, and after a night's sleep,
    /// though the phone was awake for less, the question goes to the tool again, here stopped.
    #[tokio::test(flavor = "current_thread")]
    async fn an_answer_kept_through_the_tool_runs_out_in_a_sleep() {
        let clock = super::super::clock::ManualClock::at(1_794_873_600_000);
        let mut shared = shared();
        shared.clock = clock.clone();
        let shared = Arc::new(shared);
        let txt = query(b"\x07example\x03com\x00", 16);
        let mut kept = txt.clone();
        kept[2] = 0x81;
        kept[3] = 0x80;
        kept[7] = 1;
        kept.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 1, 0x2c, 0, 3, 2, b'h', b'i']);
        lock(&shared.tool_answers).insert(&kept, shared.clock.since_boot());
        let rcode = |answer: Option<Vec<u8>>| answer.and_then(|a| a.get(3).map(|f| f & 0x0f));
        clock.pass(299_000);
        assert_eq!(
            rcode(answer(&shared, &chain(), &txt, None).await),
            Some(0),
            "kept"
        );
        clock.pass(8 * 3_600_000);
        assert_eq!(
            rcode(answer(&shared, &chain(), &txt, None).await),
            Some(2),
            "asked of the stopped tool"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fails_other_questions_when_the_tool_is_stopped() {
        let shared = Arc::new(shared());
        let txt = query(b"\x07example\x03com\x00", 16);
        let Some(answer) = answer(&shared, &chain(), &txt, None).await else {
            unreachable!("an answer")
        };
        assert_eq!(answer[3] & 0x0f, 2, "server failure");
        assert_eq!(answer[..2], [0x12, 0x34]);
    }
}
