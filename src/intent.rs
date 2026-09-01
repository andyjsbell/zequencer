use serde::{Deserialize, Serialize};
use serde_with::{IfIsHumanReadable, hex::Hex, serde_as};
use sha3::{Digest, Keccak256};
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

impl IntentId {
    pub fn parse(s: &str) -> Option<Self> {
        let bytes: [u8; 32] = hex::decode(s).ok()?.try_into().ok()?;
        Some(IntentId(bytes))
    }
}

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

impl Intent {
    /// Keccak over the canonical encoding of every economic field.
    pub fn id(&self) -> IntentId {
        let mut h = Keccak256::new();
        h.update(b"INTENT-V1");
        h.update(self.submitter.0);
        h.update(self.nonce.to_le_bytes());
        // Length-prefixed: otherwise ("AB","C") and ("A","BC") hash alike.
        h.update((self.market.base.len() as u64).to_le_bytes());
        h.update(self.market.base.as_bytes());
        h.update((self.market.quote.len() as u64).to_le_bytes());
        h.update(self.market.quote.as_bytes());
        h.update([self.side as u8]);
        h.update(self.size.to_le_bytes());
        h.update(self.max_slippage_bps.to_le_bytes());
        h.update(self.priority_fee.to_le_bytes());
        h.update(self.timestamp_ms.to_le_bytes());
        h.update(self.deadline_ms.to_le_bytes());
        IntentId(h.finalize().into())
    }
}

pub const TEST_NOW: u64 = 1_700_000_000_000;

pub fn dummy(n: u64) -> Intent {
    Intent {
        submitter: Address([n as u8; 20]),
        nonce: n,
        market: Market {
            base: "ETH".into(),
            quote: "USDC".into(),
        },
        side: Side::Buy,
        size: 1_000_000_000_000_000_000, // 1 ETH in wei
        max_slippage_bps: 50,
        priority_fee: 0,
        timestamp_ms: TEST_NOW + n,
        deadline_ms: TEST_NOW + 60_000 + n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// The id is persisted in the log and dedupes admission, so its encoding is
    /// a wire format: changing it silently would break replay of an existing
    /// database. This vector makes any such change loud.
    const DUMMY_ZERO_ID: &str = "84d00be013f73c5ffd5d6379e6ca0fb0fb2473aea6bde8b388ff42c59b5cbcab";

    #[test]
    fn the_id_of_a_known_intent_is_stable() {
        assert_eq!(hex::encode(dummy(0).id().0), DUMMY_ZERO_ID);
    }

    #[test]
    fn the_same_intent_always_hashes_the_same() {
        assert_eq!(dummy(7).id(), dummy(7).id());
        assert_eq!(dummy(7).clone().id(), dummy(7).id());
    }

    #[test]
    fn every_economic_field_feeds_the_id() {
        let base = dummy(0);
        let variants: Vec<(&str, Intent)> = vec![
            (
                "submitter",
                Intent {
                    submitter: Address([0xaa; 20]),
                    ..base.clone()
                },
            ),
            (
                "nonce",
                Intent {
                    nonce: base.nonce + 1,
                    ..base.clone()
                },
            ),
            (
                "market.base",
                Intent {
                    market: Market {
                        base: "BTC".into(),
                        ..base.market.clone()
                    },
                    ..base.clone()
                },
            ),
            (
                "market.quote",
                Intent {
                    market: Market {
                        quote: "DAI".into(),
                        ..base.market.clone()
                    },
                    ..base.clone()
                },
            ),
            (
                "side",
                Intent {
                    side: Side::Sell,
                    ..base.clone()
                },
            ),
            (
                "size",
                Intent {
                    size: base.size + 1,
                    ..base.clone()
                },
            ),
            (
                "max_slippage_bps",
                Intent {
                    max_slippage_bps: base.max_slippage_bps + 1,
                    ..base.clone()
                },
            ),
            (
                "priority_fee",
                Intent {
                    priority_fee: base.priority_fee + 1,
                    ..base.clone()
                },
            ),
            (
                "timestamp_ms",
                Intent {
                    timestamp_ms: base.timestamp_ms + 1,
                    ..base.clone()
                },
            ),
            (
                "deadline_ms",
                Intent {
                    deadline_ms: base.deadline_ms + 1,
                    ..base.clone()
                },
            ),
        ];

        for (field, variant) in &variants {
            assert_ne!(
                base.id(),
                variant.id(),
                "an intent differing only in {field} must not share an id"
            );
        }

        let ids: HashSet<IntentId> = variants
            .iter()
            .map(|(_, v)| v.id())
            .chain([base.id()])
            .collect();
        assert_eq!(
            ids.len(),
            variants.len() + 1,
            "each field must occupy its own place in the preimage"
        );
    }

    #[test]
    fn market_strings_are_length_prefixed() {
        // The case the length prefix exists for: without it both intents hash
        // the concatenation "ABC" and collide.
        let split_one = Intent {
            market: Market {
                base: "AB".into(),
                quote: "C".into(),
            },
            ..dummy(0)
        };
        let split_other = Intent {
            market: Market {
                base: "A".into(),
                quote: "BC".into(),
            },
            ..dummy(0)
        };
        assert_ne!(split_one.id(), split_other.id());
    }

    #[test]
    fn distinct_intents_get_distinct_ids() {
        let ids: HashSet<IntentId> = (0..64).map(|n| dummy(n).id()).collect();
        assert_eq!(ids.len(), 64);
    }
}
