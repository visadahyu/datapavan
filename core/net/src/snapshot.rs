//! What the live view "Now" draws (ADR 0046, decision 2 (d)), as the engine hands it to Watch's Kotlin
//! side once a second while the view is open: each app's bytes by its state in each window, and the
//! destinations it reached, from memory only. Version 3, little-endian:
//!
//! - version (3), when it was taken (milliseconds since 1970, UTC), what the latest reading of the
//!   states knew (0 none came yet, 1 the states, 2 nothing: Watch has no usage access, 3 nothing: Android
//!   gave no events, as before the first unlock after a restart), the end of what was told, the screen
//!   (0 off, 1 on, 2 not known), when it last came on (0 not known), the window "while the screen was
//!   off": when the screen went off (0 for no window: it has not gone off since Watch started, or the live
//!   memory was cleared since) and came on again (0 while it is still off), then a count (u32) of apps;
//! - each app: its UID (`u32::MAX` for flows Android named no app for), its state now (the code of
//!   [`Placed::code`], or 4 while the last second told does not place it), flags (bit 0: the user's
//!   circumvention tool, which carries the chained apps' traffic; bit 1: it went through the tool, its
//!   destinations not kept), then its bytes up and down for each window (the last 10 minutes, the last
//!   hour, since the screen came on, while the screen was off) and each column (no state, in use, with
//!   its notification, in the background, not told yet, then the bytes in no state by why: no usage
//!   access, no events, told too late, no app, not told): 80 numbers (u64), window by window; then a
//!   count (u16) of destinations;
//! - each destination: protocol, where its name came from, ECH, the app's own DNS, flags (bit 0: it
//!   came in), its address (length 4 or 16, then the bytes) and port, the AS number (0 none) and what its
//!   owner is, then its name, the DNS name beside it where the two differ, the known resolver and the
//!   organisation behind its network, each a length byte and UTF-8, and its bytes up and down for each
//!   window: 6 numbers; then its route, as the log writes it: a byte (0 directly, 1 through the tool, 2
//!   through a `WireGuard` tunnel) and the tunnel's number (u32, 0 for none);
//! - after each app's destinations, the `WireGuard` tunnel it went through with its destinations left out
//!   ("Log where these apps connect" off), in a window: its number (u32), 0 for none.
//!
//! The windows of 10 minutes and an hour are whole minutes: the current one and the 9, or the 59, before
//! it, so that they reach back at least 9 and 59 minutes and never more than 10 and 60. The window while
//! the screen was off holds no destinations. The codes of where a name came from, ECH, DNS and the owner
//! are the log's (`log.rs`).
//!
//! Version 2 (W5's third part) added the window while the screen was off and the bytes in no state by
//! why; version 3 (W7, part 1) each destination's route and each app's tunnel. Both sides ship in one build,
//! so the Kotlin side reads version 3 only.

use crate::engine::{Flow, Network};
use crate::log::{
    dns_code, ech_code, named_by_code, push_address, push_network, push_text, push_via,
};
use crate::states::{Known, Placed, Screen};

/// The version of the snapshot.
pub const VERSION: u8 = 3;

/// Bytes up and down.
pub type Ways = [u64; 2];

/// The windows of an app's bytes: the last 10 minutes, the last hour, since the screen came on, while the
/// screen was off.
pub const WINDOWS: usize = 4;

/// The window while the screen was off.
pub const OFF: usize = 3;

/// The columns of an app's bytes in each window: no state, in use, with its notification, in the
/// background, not told yet, then the bytes in no state by why (no usage access, no events, told too
/// late, no app, not told).
pub const COLUMNS: usize = 10;

/// The live view at one moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// When it was taken, in milliseconds since 1970 (UTC).
    pub taken: u64,
    /// What the latest reading of the states knew, if one came.
    pub known: Option<Known>,
    /// The end of what was told of the states.
    pub told_until: u64,
    /// The screen, as last told.
    pub screen: Screen,
    /// When the screen last came on: the start of the window "since the screen came on".
    pub session: Option<u64>,
    /// The window "while the screen was off": when the screen went off, and came on again if it did.
    pub off: Option<(u64, Option<u64>)>,
    /// The apps with bytes in a window, by UID.
    pub apps: Vec<AppNow>,
}

/// An app in the live view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppNow {
    /// Its UID, `None` for flows Android named no app for.
    pub uid: Option<u32>,
    /// Its state in the last second told, `None` while that second does not place it.
    pub now: Option<Placed>,
    /// Whether it is the user's circumvention tool, which carries the chained apps' traffic.
    pub tool: bool,
    /// Whether it went through the tool with its destinations left out, in a window.
    pub through_tool: bool,
    /// The `WireGuard` tunnel it went through with its destinations left out, in a window (W7).
    pub through_tunnel: Option<u32>,
    /// Whether it is the user's tool with its own servers left out, as they are while "Log where these apps
    /// connect" is off (ADR 0046, decision 3, as decided on 2026-11-19), so that the view says why it shows
    /// none rather than guess it from an empty list.
    pub servers_hidden: bool,
    /// Its bytes up and down, by window ([`WINDOWS`]), then by column ([`COLUMNS`]).
    pub bytes: [[Ways; COLUMNS]; WINDOWS],
    /// The destinations it reached in a window.
    pub places: Vec<PlaceNow>,
}

/// A destination in the live view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaceNow {
    /// The latest flow to it: protocol, address and port, name, where the name came from, the DNS name
    /// beside it, ECH, the app's own DNS and the known resolver, whether it came in, its network.
    pub flow: Flow,
    /// The network and organisation behind its address, where the organisation table names them.
    pub organisation: Option<(Network, String)>,
    /// Its bytes up and down, by window.
    pub bytes: [Ways; 3],
}

/// The snapshot in its stored form.
#[must_use]
pub fn encode(snapshot: &Snapshot) -> Vec<u8> {
    let mut out = vec![VERSION];
    out.extend_from_slice(&snapshot.taken.to_le_bytes());
    out.push(match snapshot.known {
        None => 0,
        Some(Known::States) => 1,
        Some(Known::NoAccess) => 2,
        Some(Known::Locked) => 3,
    });
    out.extend_from_slice(&snapshot.told_until.to_le_bytes());
    out.push(match snapshot.screen {
        Screen::Off => 0,
        Screen::On(_) => 1,
        Screen::Unknown => 2,
    });
    out.extend_from_slice(&snapshot.session.unwrap_or(0).to_le_bytes());
    let (off, on) = snapshot
        .off
        .map_or((0, 0), |(off, on)| (off, on.unwrap_or(0)));
    out.extend_from_slice(&off.to_le_bytes());
    out.extend_from_slice(&on.to_le_bytes());
    out.extend_from_slice(
        &u32::try_from(snapshot.apps.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for app in &snapshot.apps {
        out.extend_from_slice(&app.uid.unwrap_or(u32::MAX).to_le_bytes());
        out.push(app.now.map_or(4, Placed::code));
        out.push(
            u8::from(app.tool)
                | u8::from(app.through_tool) << 1
                | u8::from(app.servers_hidden) << 2,
        );
        for window in &app.bytes {
            for ways in window {
                push_ways(&mut out, *ways);
            }
        }
        let places = app.places.len().min(usize::from(u16::MAX));
        out.extend_from_slice(&u16::try_from(places).unwrap_or(u16::MAX).to_le_bytes());
        for place in &app.places[..places] {
            let flow = &place.flow;
            out.push(flow.protocol);
            out.push(named_by_code(flow.named_by));
            out.push(ech_code(flow.ech));
            out.push(dns_code(flow.dns));
            out.push(u8::from(flow.came_in));
            push_address(&mut out, flow.destination);
            let network = place.organisation.as_ref().map(|o| o.0).or(flow.network);
            push_network(&mut out, network);
            push_text(&mut out, flow.name.as_deref());
            push_text(&mut out, flow.dns_name.as_deref());
            push_text(&mut out, flow.resolver.as_deref());
            push_text(&mut out, place.organisation.as_ref().map(|o| o.1.as_str()));
            for ways in place.bytes {
                push_ways(&mut out, ways);
            }
            push_via(&mut out, flow.via);
        }
        out.extend_from_slice(&app.through_tunnel.unwrap_or(0).to_le_bytes());
    }
    out
}

fn push_ways(out: &mut Vec<u8>, ways: Ways) {
    out.extend_from_slice(&ways[0].to_le_bytes());
    out.extend_from_slice(&ways[1].to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{DnsUse, Ech, NamedBy, Outcome};
    use crate::owners::NetworkKind;
    use crate::states::{State, Unknown};
    use std::net::SocketAddr;

    fn place() -> PlaceNow {
        PlaceNow {
            flow: Flow {
                id: 7,
                protocol: 6,
                app: SocketAddr::from(([10, 1, 10, 1], 40_000)),
                destination: SocketAddr::from(([93, 184, 216, 34], 443)),
                uid: Some(10_123),
                outcome: Outcome::Opened,
                name: Some("other.example".into()),
                named_by: NamedBy::Tls,
                dns_name: Some("www.example.com".into()),
                came_in: true,
                ech: Ech::Offered,
                dns: DnsUse::Encrypted,
                resolver: Some("sample".into()),
                network: None,
                via: crate::engine::Via::Direct,
            },
            organisation: Some((
                Network {
                    asn: 15_133,
                    kind: NetworkKind::Hosting,
                },
                "Edgecast".into(),
            )),
            bytes: [[1, 2], [3, 4], [5, 6]],
        }
    }

    /// Field by field, so that the Kotlin side's reader is checked against the same layout.
    #[test]
    fn a_snapshot_is_laid_out_field_by_field() {
        let mut bytes = [[[0; 2]; COLUMNS]; WINDOWS];
        bytes[1][3] = [100, 200];
        bytes[3][7] = [7, 8];
        let snapshot = Snapshot {
            taken: 1_000,
            known: Some(Known::NoAccess),
            told_until: 900,
            screen: Screen::On(Some(500)),
            session: Some(500),
            off: Some((300, Some(500))),
            apps: vec![AppNow {
                uid: Some(10_123),
                now: Some(Placed::Known(State::Background)),
                tool: false,
                through_tool: true,
                through_tunnel: None,
                servers_hidden: false,
                bytes,
                places: vec![place()],
            }],
        };
        let out = encode(&snapshot);
        let mut expected = vec![3];
        expected.extend_from_slice(&1_000u64.to_le_bytes());
        expected.push(2);
        expected.extend_from_slice(&900u64.to_le_bytes());
        expected.push(1);
        for time in [500u64, 300, 500] {
            expected.extend_from_slice(&time.to_le_bytes());
        }
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&10_123u32.to_le_bytes());
        expected.extend_from_slice(&[3, 0b10]);
        for window in 0..4 {
            for column in 0..10 {
                let ways: [u64; 2] = match (window, column) {
                    (1, 3) => [100, 200],
                    (3, 7) => [7, 8],
                    _ => [0, 0],
                };
                expected.extend_from_slice(&ways[0].to_le_bytes());
                expected.extend_from_slice(&ways[1].to_le_bytes());
            }
        }
        expected.extend_from_slice(&1u16.to_le_bytes());
        expected.extend_from_slice(&[6, 1, 1, 2, 1, 4, 93, 184, 216, 34]);
        expected.extend_from_slice(&443u16.to_le_bytes());
        expected.extend_from_slice(&15_133u32.to_le_bytes());
        expected.push(2);
        for text in ["other.example", "www.example.com", "sample", "Edgecast"] {
            expected.push(u8::try_from(text.len()).unwrap_or(0));
            expected.extend_from_slice(text.as_bytes());
        }
        for value in [1u64, 2, 3, 4, 5, 6] {
            expected.extend_from_slice(&value.to_le_bytes());
        }
        // Version 3: the destination's route, directly, and the app's tunnel, none.
        expected.extend_from_slice(&[0, 0, 0, 0, 0]);
        expected.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(out, expected);
    }

    /// An app with no UID, a state not told yet, the tool, nothing known, the screen off: each in its
    /// own code.
    #[test]
    fn the_codes_of_what_is_not_known() {
        let snapshot = Snapshot {
            taken: 1,
            known: None,
            told_until: 0,
            screen: Screen::Off,
            session: None,
            off: Some((700, None)),
            apps: vec![
                AppNow {
                    uid: None,
                    now: Some(Placed::Unknown(Unknown::NoApp)),
                    tool: false,
                    through_tool: false,
                    through_tunnel: None,
                    servers_hidden: false,
                    bytes: [[[0; 2]; COLUMNS]; WINDOWS],
                    places: Vec::new(),
                },
                AppNow {
                    uid: Some(10_200),
                    now: None,
                    tool: true,
                    through_tool: false,
                    through_tunnel: None,
                    servers_hidden: true,
                    bytes: [[[0; 2]; COLUMNS]; WINDOWS],
                    places: Vec::new(),
                },
            ],
        };
        let out = encode(&snapshot);
        assert_eq!(
            (out[9], out[18]),
            (0, 0),
            "nothing told yet, the screen off"
        );
        assert_eq!(
            (&out[19..27], &out[35..43], &out[43..47]),
            (&[0; 8][..], &[0; 8][..], &[2, 0, 0, 0][..]),
            "the screen did not come on, and is still off"
        );
        assert_eq!(&out[27..35], &700u64.to_le_bytes()[..]);
        let first = 1 + 8 + 1 + 8 + 1 + 8 + 8 + 8 + 4;
        // An app of no destinations ends with its tunnel's number, none (version 3).
        let app = 4 + 1 + 1 + 80 * 8 + 2 + 4;
        assert_eq!(out[first..first + 6], [0xff, 0xff, 0xff, 0xff, 0x40, 0]);
        assert_eq!(
            out[first + app + 4..first + app + 6],
            [4, 0b101],
            "not placed yet; the tool, its servers left out"
        );
        assert_eq!(out.len(), first + 2 * app);
        // No window while the screen was off: both times 0.
        let none = encode(&Snapshot {
            off: None,
            ..snapshot
        });
        assert_eq!(&none[27..43], &[0; 16][..]);
    }
}
