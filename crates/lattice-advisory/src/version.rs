//! Typed firmware version comparison.
//!
//! Vendor firmware strings are free text. This module only claims an ordering
//! when both sides parse into the same shape; anything else is `None` and the
//! caller must degrade to "possible" rather than assert a match or a
//! contradiction.
//!
//! Bound syntax carried inside the existing [`crate::VersionConstraint`]
//! strings (so the stored column layout does not change):
//! - a lower bound is `>=V` (inclusive, also the bare legacy form `V`) or `>V`
//! - an upper bound is `<=V` (inclusive, also the bare legacy `Range` form) or
//!   `<V` (exclusive, also the legacy `LessThan(V)` form)
//! - `*` as a `Range` bound means unbounded on that side

use std::cmp::Ordering;

/// A parsed version: numeric core plus an optional pre-release style tail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Version {
    core: Vec<u64>,
    tail: String,
}

impl Version {
    /// Parses `1.2.3`, `v1.2.3`, `V1.2.3+build7`, `1.2.3-rc1`. Returns `None`
    /// when no leading dotted numeric core exists.
    pub fn parse(raw: &str) -> Option<Self> {
        let mut text = raw.trim();
        if let Some(rest) = text.strip_prefix(['v', 'V']) {
            text = rest;
        }
        // Build metadata never participates in ordering.
        if let Some((head, _)) = text.split_once('+') {
            text = head;
        }
        let split = text
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(text.len());
        let (core_text, tail) = text.split_at(split);
        let core_text = core_text.trim_end_matches('.');
        if core_text.is_empty() {
            return None;
        }
        let mut core = Vec::new();
        for part in core_text.split('.') {
            if part.is_empty() {
                return None;
            }
            core.push(part.parse::<u64>().unwrap_or(u64::MAX));
            if core.len() > 16 {
                return None;
            }
        }
        while core.len() > 1 && core.last() == Some(&0) {
            core.pop();
        }
        Some(Self {
            core,
            tail: tail.trim().to_ascii_lowercase(),
        })
    }

    /// `None` when the two versions share a core but differ in tail, because
    /// "1.2-rc1" versus "1.2-build5" has no defensible order.
    pub fn compare(&self, other: &Self) -> Option<Ordering> {
        match self.core.cmp(&other.core) {
            Ordering::Equal if self.tail == other.tail => Some(Ordering::Equal),
            Ordering::Equal => None,
            order => Some(order),
        }
    }
}

/// Whether a device value satisfies a constraint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Applies {
    Yes,
    No,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Side {
    Lower,
    Upper,
}

/// Splits a bound string into (version text, inclusive). `None` = unbounded.
fn split_bound(raw: &str, default_inclusive: bool) -> Option<(&str, bool)> {
    if raw == "*" {
        return None;
    }
    let (text, inclusive) = if let Some(v) = raw.strip_prefix(">=") {
        (v, true)
    } else if let Some(v) = raw.strip_prefix("<=") {
        (v, true)
    } else if let Some(v) = raw.strip_prefix('>') {
        (v, false)
    } else if let Some(v) = raw.strip_prefix('<') {
        (v, false)
    } else {
        (raw, default_inclusive)
    };
    Some((text, inclusive))
}

fn check(device: &Version, bound: Option<(&str, bool)>, side: Side) -> Applies {
    let Some((text, inclusive)) = bound else {
        return Applies::Yes;
    };
    let Some(limit) = Version::parse(text) else {
        return Applies::Unknown;
    };
    match device.compare(&limit) {
        None => Applies::Unknown,
        Some(Ordering::Equal) if inclusive => Applies::Yes,
        Some(Ordering::Equal) => Applies::No,
        Some(Ordering::Less) if side == Side::Upper => Applies::Yes,
        Some(Ordering::Greater) if side == Side::Lower => Applies::Yes,
        Some(_) => Applies::No,
    }
}

fn and(a: Applies, b: Applies) -> Applies {
    match (a, b) {
        (Applies::No, _) | (_, Applies::No) => Applies::No,
        (Applies::Unknown, _) | (_, Applies::Unknown) => Applies::Unknown,
        _ => Applies::Yes,
    }
}

/// Exact: equal after normalisation. Unparsable on either side falls back to
/// a case-insensitive string compare; inequality there is `Unknown`, never `No`.
pub fn exact_applies(constraint: &str, device: &str) -> Applies {
    match (Version::parse(constraint), Version::parse(device)) {
        (Some(a), Some(b)) => match a.compare(&b) {
            Some(Ordering::Equal) => Applies::Yes,
            Some(_) => Applies::No,
            None => Applies::Unknown,
        },
        _ if constraint.eq_ignore_ascii_case(device) => Applies::Yes,
        _ => Applies::Unknown,
    }
}

/// `LessThan(max)` is exclusive unless the string carries `<=`.
pub fn less_than_applies(max: &str, device: &str) -> Applies {
    let Some(device) = Version::parse(device) else {
        return Applies::Unknown;
    };
    check(&device, split_bound(max, false), Side::Upper)
}

/// `Range{min,max}`: bare bounds are inclusive; `>`/`<` make them exclusive.
pub fn range_applies(min: &str, max: &str, device: &str) -> Applies {
    let Some(device) = Version::parse(device) else {
        return Applies::Unknown;
    };
    and(
        check(&device, split_bound(min, true), Side::Lower),
        check(&device, split_bound(max, true), Side::Upper),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_table() {
        let cases = [
            ("v1.2.3", "1.2.3", Applies::Yes),
            ("1.2.3", "V1.2.3", Applies::Yes),
            ("1.2", "1.2.0", Applies::Yes),
            ("1.2.3+build7", "1.2.3", Applies::Yes),
            ("1.2.3", "1.2.4", Applies::No),
            ("1.10", "1.9", Applies::No),
            ("1.2-rc1", "1.2", Applies::Unknown),
            ("ABC", "abc", Applies::Yes),
            ("abc", "def", Applies::Unknown),
        ];
        for (c, d, want) in cases {
            assert_eq!(exact_applies(c, d), want, "{c} vs {d}");
        }
    }

    #[test]
    fn bounds_table() {
        assert_eq!(less_than_applies("2.1", "3.0"), Applies::No);
        assert_eq!(less_than_applies("2.1", "2.0.9"), Applies::Yes);
        assert_eq!(less_than_applies("2.1", "2.1"), Applies::No);
        assert_eq!(less_than_applies("<=2.1", "2.1"), Applies::Yes);
        assert_eq!(less_than_applies("2.1", "garbage"), Applies::Unknown);
        assert_eq!(range_applies(">=1.0", "<2.0", "1.0"), Applies::Yes);
        assert_eq!(range_applies(">=1.0", "<2.0", "2.0"), Applies::No);
        assert_eq!(range_applies(">1.0", "<=2.0", "1.0"), Applies::No);
        assert_eq!(range_applies(">1.0", "<=2.0", "2.0"), Applies::Yes);
        assert_eq!(range_applies("1.0", "2.0", "2.0"), Applies::Yes);
        assert_eq!(range_applies(">=2.0", "*", "9.9"), Applies::Yes);
        assert_eq!(range_applies(">=2.0", "*", "1.9"), Applies::No);
        assert_eq!(range_applies("*", "<2.0", "1.9"), Applies::Yes);
        assert_eq!(range_applies(">=1.0", "<2.0", "x"), Applies::Unknown);
    }
}
