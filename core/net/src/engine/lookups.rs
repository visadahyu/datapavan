//! The lookups of chained apps (ADR 0038): Watch answers A, AAAA and reverse lookups of stand-ins
//! itself, and asks Quad9's service without blocking for every other question, as DNS over TCP through
//! the tool on a connection it keeps ([`super::kept`]), so that no lookup of a chained app reaches the
//! network beneath.

use super::chain::Chain;
use super::{Shared, kept, lock};
use crate::answers::{self, A, AAAA};
use crate::standins::is_stand_in;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Quad9's service without blocking, `quad9-unsecured` in `data/resolvers`: the resolver of chained
/// apps' other questions until the user chooses one (ADR 0038, decided by the maintainer).
pub(super) const RESOLVERS: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 10)), 53),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(149, 112, 112, 10)), 53),
];

/// How long a question through the tool may take, for each resolver address in turn. Android's
/// resolver gives up on a lookup after about five seconds and asks again.
pub(super) const LOOKUP_TIMEOUT: Duration = Duration::from_secs(4);

/// The answer to a chained app's `query`, or `None` when it is not even a DNS message with an ID.
pub(super) async fn answer(
    shared: &Arc<Shared>,
    chain: &Arc<Chain>,
    query: &[u8],
) -> Option<Vec<u8>> {
    let Some(question) = answers::question(query) else {
        return answers::failure(query);
    };
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
    // Asked before: the answer Watch keeps for the tool's route, for its time to live, so that each name
    // costs one trip through the tool, not one per lookup (ADR 0038).
    let kept = lock(&shared.tool_answers).answer(query, Instant::now());
    if let Some(kept) = kept {
        return answers::rebuilt(&kept).or_else(|| answers::failure(query));
    }
    match through_tool(shared, chain, query).await {
        Ok(answer) => {
            lock(&shared.tool_answers).insert(&answer, Instant::now());
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

    #[tokio::test(flavor = "current_thread")]
    async fn answers_a_aaaa_and_reverse_lookups_here() {
        let shared = Arc::new(shared());
        let chain = chain();
        let a = query(b"\x07example\x03com\x00", A);
        let Some(answer) = answer(&shared, &chain, &a).await else {
            unreachable!("an answer")
        };
        let Some(read) = dns::response(&answer) else {
            unreachable!("a response")
        };
        assert_eq!(
            read.addresses,
            vec![(Ipv4Addr::new(198, 18, 0, 1).into(), 0)]
        );
        let Some(again) = super::answer(&shared, &chain, &a).await else {
            unreachable!("an answer")
        };
        assert_eq!(again, answer, "the same stand-in");
        let Some(empty) =
            super::answer(&shared, &chain, &query(b"\x07example\x03com\x00", AAAA)).await
        else {
            unreachable!("an answer")
        };
        assert_eq!(empty[6..8], [0, 0]);
        let ptr = query(
            b"\x011\x010\x0218\x03198\x07in-addr\x04arpa\x00",
            answers::TYPE_PTR,
        );
        let Some(reverse) = super::answer(&shared, &chain, &ptr).await else {
            unreachable!("an answer")
        };
        assert!(reverse.ends_with(b"\x07example\x03com\x00"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fails_other_questions_when_the_tool_is_stopped() {
        let shared = Arc::new(shared());
        let txt = query(b"\x07example\x03com\x00", 16);
        let Some(answer) = answer(&shared, &chain(), &txt).await else {
            unreachable!("an answer")
        };
        assert_eq!(answer[3] & 0x0f, 2, "server failure");
        assert_eq!(answer[..2], [0x12, 0x34]);
    }
}
