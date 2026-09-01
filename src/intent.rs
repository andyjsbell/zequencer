use serde::{Deserialize, Serialize};
use serde_with::{IfIsHumanReadable, hex::Hex, serde_as};

/// Submitting account.
#[serde_as]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Address(#[serde_as(as = "IfIsHumanReadable<Hex>")] pub [u8; 20]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Side {
    Buy = 0,
    Sell = 1,
}

/// The asset pair an intent trades against, e.g. ETH/USDC.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Market {
    pub base: String,
    pub quote: String,
}

#[serde_as]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IntentId(#[serde_as(as = "IfIsHumanReadable<Hex>")] pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intent {
    pub submitter: Address,
    /// Per-submitter ordering counter. Admission enforces that it strictly
    /// advances; see `Admission::check`.
    pub nonce: u64,
    pub market: Market,
    pub side: Side,
    /// Integer base units (wei-style). Never a float: sequencing has to be
    /// reproducible, and float rounding is not.
    pub size: u128,
    /// Risk control, in basis points. 10_000 bps = 100%.
    pub max_slippage_bps: u16,
    /// What the submitter bids for position within its ordering domain.
    /// See `order_domain` for exactly how it competes with arrival time.
    pub priority_fee: u64,
    /// When the client created the intent. Distinct from `received_at`, which
    /// is when the sequencer admitted it.
    pub timestamp_ms: u64,
    /// Client-declared expiry.
    pub deadline_ms: u64,
}