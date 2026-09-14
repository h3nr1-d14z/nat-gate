//! nftables-native backend for nat-gate.
//!
//! Uses a dedicated `nat-gate` table (per family) instead of iptables'
//! built-in nat chains. Shares the `RuleStore` model with the iptables
//! backend so all listing, logging, and TUI code is backend-agnostic.

pub mod executor;
pub mod rulestore;
