//! The lookups of chained apps (ADR 0038): Watch answers A, AAAA and reverse lookups of stand-ins
//! itself, and asks Quad9's service without blocking for every other question, as DNS over TCP through
//! the tool, so that no lookup of a chained app reaches the network beneath.

use super::chain::{Chain, connect_proxy, io_error};
use super::{Shared, lock};
use crate::answers::{self, A, AAAA};
use crate::socks5::{self, Command, Target};
use crate::standins::is_stand_in;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Quad9's service without blocking, `quad9-unsecured` in `data/resolvers`: the resolver of chained
/// apps' other questions until the user chooses one (ADR 0038, decided by the maintainer).
pub(super) const RESOLVERS: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 10)), 53),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(149, 112, 112, 10)), 53),
];

/// How long a question through the tool may take, for each resolver address in turn. Android's
/// resolver gives up on a lookup after about five seconds and asks again.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(4);

/// The answer to a chained app's `query`, or `None` when it is not even a DNS message with an ID.
pub(super) async fn answer(shared: &Arc<Shared>, chain: &Chain, query: &[u8]) -> Option<Vec<u8>> {
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
    match through_tool(shared, chain, query).await {
        Ok(answer) => answers::rebuilt(&answer).or_else(|| answers::failure(query)),
        Err(_) => answers::failure(query),
    }
}

/// Asks the resolvers in turn, through the tool.
async fn through_tool(shared: &Arc<Shared>, chain: &Chain, query: &[u8]) -> io::Result<Vec<u8>> {
    let mut last = io::Error::from(io::ErrorKind::HostUnreachable);
    for resolver in RESOLVERS {
        match tokio::time::timeout(LOOKUP_TIMEOUT, ask(shared, chain, resolver, query)).await {
            Ok(Ok(answer)) => return Ok(answer),
            Ok(Err(error)) => last = error,
            Err(_) => last = io::ErrorKind::TimedOut.into(),
        }
    }
    Err(last)
}

/// One question as DNS over TCP (RFC 7766) to `resolver`, through the tool: the answer, if its ID is the
/// question's.
async fn ask(
    shared: &Arc<Shared>,
    chain: &Chain,
    resolver: SocketAddr,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    let length = u16::try_from(query.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    let mut stream = connect_proxy(shared, chain.proxy).await?;
    socks5::handshake(
        &mut stream,
        chain.credentials.as_ref(),
        Command::Connect,
        &Target::Address(resolver),
    )
    .await
    .map_err(io_error)?;
    let mut framed = length.to_be_bytes().to_vec();
    framed.extend_from_slice(query);
    stream.write_all(&framed).await?;
    let mut prefix = [0; 2];
    stream.read_exact(&mut prefix).await?;
    let mut answer = vec![0; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut answer).await?;
    if answer.get(..2) != query.get(..2) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(answer)
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
