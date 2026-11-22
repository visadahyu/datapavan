//! `WireGuard` as the network part's upstream for the apps the user picks (W7, ADR 0035): the configuration
//! (`wg-quick`'s format, [`config`]), the protocol core behind a small trait ([`core`], `GotaTun`'s
//! `noise::Tunn`), and the address swap that forwards a chosen app's own packets into the session
//! ([`swap`], option 3). The engine's tunnels (`engine::tunnels`) put them together: one per
//! configuration, each with its protected UDP socket, its timers and its flows.

pub mod config;
pub mod core;
pub mod swap;

pub use config::{Config, Refusal};
