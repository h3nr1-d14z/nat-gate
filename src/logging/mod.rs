//! Connection logging for nat-gate.
//!
//! Because forwarded traffic is MASQUERADE'd, the game server only ever sees
//! the gateway's Tailscale IP — the original client address exists solely in
//! the gateway's conntrack table. These modules capture it there:
//!
//! - [`events`]: parse `conntrack -E` / `conntrack -L` output
//! - [`filter`]: classify flows against active nat-gate rules
//! - [`store`]: append-only JSONL storage with size-based rotation
//! - [`daemon`]: the event loop behind `nat-gate log daemon`

pub mod daemon;
pub mod events;
pub mod filter;
pub mod store;

/// Default on-disk location for the connection log.
pub const LOG_DIR: &str = "/var/lib/nat-gate";
/// Default log file name inside LOG_DIR.
pub const LOG_FILE: &str = "connections.jsonl";
