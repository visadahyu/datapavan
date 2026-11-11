//! Connections to the resolvers of chained apps' other questions, through the tool, kept open and shared
//! by the questions (RFC 7766): one connection for each resolver, on which questions are pipelined,
//! each under an ID of the connection's own, and answers are matched to their questions by that ID and
//! by the question they repeat, whatever their order. A question then costs one round trip through the
//! tool, not a connection to the tool, a SOCKS5 handshake and a connection to the resolver first.
//! Android's own DNS over TLS keeps its connections the same way.

use super::chain::{Chain, connect_proxy, io_error};
use super::lookups::LOOKUP_TIMEOUT;
use super::{Shared, lock};
use crate::answers;
use crate::dns::{read_name, u16_at};
use crate::socks5::{self, Command, Target};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

/// How long a connection stays open with no question waiting. RFC 7766 asks clients to close idle
/// connections; a resolver that closes one sooner is seen at once, as its end arrives.
const IDLE: Duration = Duration::from_secs(10);

/// How many questions may wait for their answers on one connection; more wait for room.
const IN_FLIGHT: usize = 64;

/// A kept connection, as the engine holds it.
pub(super) struct Kept {
    chain: Arc<Chain>,
    resolver: SocketAddr,
    questions: mpsc::Sender<Asked>,
}

/// A question for the connection, and where its answer goes.
struct Asked {
    query: Vec<u8>,
    answer: oneshot::Sender<io::Result<Vec<u8>>>,
}

/// A question the connection sent, waiting for its answer.
struct Waiting {
    /// The query's own ID, which the answer gets back.
    id: [u8; 2],
    /// The question, as the answer must repeat it.
    question: (String, u16, u16),
    answer: oneshot::Sender<io::Result<Vec<u8>>>,
    since: Instant,
}

/// Asks `resolver` through `chain`'s tool on the kept connection: the answer, under the query's own ID.
pub(super) async fn ask(
    shared: &Arc<Shared>,
    chain: &Arc<Chain>,
    resolver: SocketAddr,
    query: &[u8],
) -> io::Result<Vec<u8>> {
    if answers::question(query).is_none() || u16::try_from(query.len()).is_err() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut last = io::Error::from(io::ErrorKind::HostUnreachable);
    // A connection that ended as the question went out, as when the resolver closed an idle one at that
    // moment, gets the question once more, on a new connection.
    for _ in 0..2 {
        let questions = connection(shared, chain, resolver);
        let (answer, answered) = oneshot::channel();
        let asked = Asked {
            query: query.to_vec(),
            answer,
        };
        if questions.send(asked).await.is_err() {
            continue;
        }
        match answered.await {
            Ok(Ok(answer)) => return Ok(answer),
            Ok(Err(error)) => last = error,
            Err(_) => {}
        }
    }
    Err(last)
}

/// The kept connection to `resolver` through `chain`'s tool, opened when there is none. A connection for
/// a chain that is no longer on serves its question and ends.
fn connection(
    shared: &Arc<Shared>,
    chain: &Arc<Chain>,
    resolver: SocketAddr,
) -> mpsc::Sender<Asked> {
    let current = lock(&shared.chain).clone();
    let is_current = |chain: &Arc<Chain>| current.as_ref().is_some_and(|c| Arc::ptr_eq(c, chain));
    let mut kept = lock(&shared.kept);
    kept.retain(|k| !k.questions.is_closed() && is_current(&k.chain));
    if let Some(k) = kept
        .iter()
        .find(|k| Arc::ptr_eq(&k.chain, chain) && k.resolver == resolver)
    {
        return k.questions.clone();
    }
    let (questions, asked) = mpsc::channel(IN_FLIGHT);
    tokio::spawn(run(Arc::clone(shared), Arc::clone(chain), resolver, asked));
    if is_current(chain) {
        kept.push(Kept {
            chain: Arc::clone(chain),
            resolver,
            questions: questions.clone(),
        });
    }
    questions
}

/// One kept connection: opens it, then sends questions and reads answers, until it has been idle for
/// [`IDLE`], the resolver or the tool ends it, a question waits longer than a lookup may, or no one can
/// send it questions any more and none waits.
async fn run(
    shared: Arc<Shared>,
    chain: Arc<Chain>,
    resolver: SocketAddr,
    mut asked: mpsc::Receiver<Asked>,
) {
    let stream = match open(&shared, &chain, resolver).await {
        Ok(stream) => stream,
        Err(error) => {
            asked.close();
            while let Some(question) = asked.recv().await {
                let _ = question.answer.send(Err(error.kind().into()));
            }
            return;
        }
    };
    let (mut reader, mut writer) = stream.into_split();
    let mut waiting: HashMap<u16, Waiting> = HashMap::new();
    let mut next_id: u16 = 0;
    let mut received = Vec::with_capacity(4096);
    let mut taking = true;
    let mut idle_since = Instant::now();
    loop {
        let oldest = waiting.values().map(|w| w.since).min();
        tokio::select! {
            question = asked.recv(), if taking && waiting.len() < IN_FLIGHT => {
                let Some(question) = question else {
                    taking = false;
                    if waiting.is_empty() {
                        return;
                    }
                    continue;
                };
                if question.answer.is_closed() {
                    // Its lookup gave up while the connection opened, as through a slow tool.
                    continue;
                }
                let Some(parsed) = answers::question(&question.query) else {
                    let _ = question.answer.send(Err(io::ErrorKind::InvalidInput.into()));
                    continue;
                };
                let id = free_id(&waiting, &mut next_id);
                let Some(framed) = framed(&question.query, id) else {
                    let _ = question.answer.send(Err(io::ErrorKind::InvalidInput.into()));
                    continue;
                };
                if writer.write_all(&framed).await.is_err() {
                    let _ = question.answer.send(Err(io::ErrorKind::ConnectionAborted.into()));
                    fail(waiting, io::ErrorKind::ConnectionAborted);
                    return;
                }
                waiting.insert(id, Waiting {
                    id: [question.query[0], question.query[1]],
                    question: (parsed.name, parsed.kind, parsed.class),
                    answer: question.answer,
                    since: Instant::now(),
                });
            }
            read = reader.read_buf(&mut received) => {
                if matches!(read, Ok(0) | Err(_)) {
                    fail(waiting, io::ErrorKind::ConnectionAborted);
                    return;
                }
                while let Some(mut message) = next_message(&mut received) {
                    let Some(id) = u16_at(&message, 0) else {
                        continue;
                    };
                    let matches = waiting
                        .get(&id)
                        .is_some_and(|w| repeats(&message, &w.question));
                    if let Some(w) = matches.then(|| waiting.remove(&id)).flatten() {
                        message[..2].copy_from_slice(&w.id);
                        let _ = w.answer.send(Ok(message));
                    }
                }
                if waiting.is_empty() {
                    if !taking {
                        return;
                    }
                    idle_since = Instant::now();
                }
            }
            () = tokio::time::sleep_until(idle_since + IDLE), if waiting.is_empty() => return,
            () = tokio::time::sleep_until(oldest.unwrap_or(idle_since) + LOOKUP_TIMEOUT), if oldest.is_some() => {
                // An answer this late will not come: a tool's connection can die without a word.
                fail(waiting, io::ErrorKind::TimedOut);
                return;
            }
        }
    }
}

/// A connection to `resolver` through `chain`'s tool.
async fn open(shared: &Arc<Shared>, chain: &Chain, resolver: SocketAddr) -> io::Result<TcpStream> {
    let mut stream = connect_proxy(shared, chain.proxy).await?;
    socks5::handshake(
        &mut stream,
        chain.credentials.as_ref(),
        Command::Connect,
        &Target::Address(resolver),
    )
    .await
    .map_err(io_error)?;
    Ok(stream)
}

/// Gives each waiting question `kind` of error.
fn fail(waiting: HashMap<u16, Waiting>, kind: io::ErrorKind) {
    for (_, w) in waiting {
        let _ = w.answer.send(Err(kind.into()));
    }
}

/// An ID no question on the connection waits under.
fn free_id(waiting: &HashMap<u16, Waiting>, next: &mut u16) -> u16 {
    loop {
        *next = next.wrapping_add(1);
        if !waiting.contains_key(next) {
            return *next;
        }
    }
}

/// `query` for DNS over TCP under `id`: its length first (RFC 7766, section 8).
fn framed(query: &[u8], id: u16) -> Option<Vec<u8>> {
    let length = u16::try_from(query.len()).ok()?;
    let mut out = Vec::with_capacity(query.len() + 2);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(query.get(2..)?);
    Some(out)
}

/// The next whole message in `received`, taken out of it, if one has arrived.
fn next_message(received: &mut Vec<u8>) -> Option<Vec<u8>> {
    let length = usize::from(u16_at(received, 0)?);
    let message = received.get(2..2 + length)?.to_vec();
    received.drain(..2 + length);
    Some(message)
}

/// Whether an answer repeats `question`, as RFC 7766 (section 7) asks before it is taken for the
/// question's; an answer that repeats no question is taken by its ID alone.
fn repeats(answer: &[u8], question: &(String, u16, u16)) -> bool {
    match u16_at(answer, 4) {
        Some(0) => true,
        Some(1) => read_name(answer, 12).is_some_and(|(name, after)| {
            name == question.0
                && u16_at(answer, after) == Some(question.1)
                && u16_at(answer, after + 2) == Some(question.2)
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: [u8; 2], name: &[u8]) -> Vec<u8> {
        let mut q = vec![id[0], id[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(name);
        q.extend_from_slice(&[0, 16, 0, 1]);
        q
    }

    #[test]
    fn frames_a_query_under_the_connections_id() {
        let q = query([0x12, 0x34], b"\x07example\x03com\x00");
        let Some(out) = framed(&q, 7) else {
            unreachable!("a frame")
        };
        assert_eq!(out[..4], [0, 29, 0, 7]);
        assert_eq!(out[4..], q[2..]);
    }

    #[test]
    fn takes_whole_messages_out_one_at_a_time() {
        let mut received = vec![0, 3, 1, 2, 3, 0, 2, 9];
        assert_eq!(next_message(&mut received), Some(vec![1, 2, 3]));
        assert_eq!(next_message(&mut received), None, "half a message");
        received.push(8);
        assert_eq!(next_message(&mut received), Some(vec![9, 8]));
        assert_eq!(received, Vec::<u8>::new());
    }

    #[test]
    fn an_answer_must_repeat_the_question() {
        let question = ("example.com".to_owned(), 16, 1);
        let mut answer = query([0, 1], b"\x07EXAMPLE\x03com\x00");
        answer[2] = 0x81;
        assert!(repeats(&answer, &question), "names match in any case");
        let other = query([0, 1], b"\x07example\x03org\x00");
        assert!(!repeats(&other, &question));
        let mut none = answer.clone();
        none[5] = 0;
        assert!(repeats(&none, &question), "no question to repeat");
    }

    #[test]
    fn ids_skip_those_in_use() {
        let mut waiting = HashMap::new();
        let (answer, _answered) = oneshot::channel();
        waiting.insert(
            1,
            Waiting {
                id: [0, 0],
                question: (String::new(), 0, 0),
                answer,
                since: Instant::now(),
            },
        );
        let mut next = 0;
        assert_eq!(free_id(&waiting, &mut next), 2);
        let mut wrapped = u16::MAX;
        assert_eq!(free_id(&waiting, &mut wrapped), 0);
    }
}
