//! The one sanitiser for text that originates on the network and is shown to the owner.
//!
//! Device names, banners, certificate subjects and similar strings are attacker controlled.
//! They must not carry control characters (log and terminal injection) or Unicode formatting
//! characters that reorder or hide neighbouring text (bidirectional overrides and isolates,
//! zero-width characters, the byte-order mark, line and paragraph separators).
//! Call [`display_text`] where evidence text is constructed rather than in each consumer.
//! It could move to `lattice-domain` next to `EvidenceFact`.

/// True for characters that must never appear in displayed device-supplied text.
pub fn is_forbidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}' // Arabic letter mark
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}' // zero-width characters and LRM/RLM
                | '\u{2028}'..='\u{202e}' // separators and embeddings/overrides
                | '\u{2060}'..='\u{206f}' // word joiner, invisible operators, isolates
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
        )
}

/// Removes forbidden characters and truncates to at most `max_bytes` UTF-8 bytes on a
/// character boundary.
pub fn display_text(value: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(value.len().min(max_bytes));
    for c in value.chars().filter(|c| !is_forbidden(*c)) {
        if out.len() + c.len_utf8() > max_bytes {
            break;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_controls_and_bidi_overrides() {
        assert_eq!(
            display_text("a\u{202e}b\u{0}c\u{1b}[31md\u{2066}e", 64),
            "abc[31mde"
        );
        assert_eq!(display_text("x\u{200b}y\u{feff}z\u{2028}", 64), "xyz");
    }

    #[test]
    fn truncates_on_a_character_boundary() {
        assert_eq!(display_text("ééé", 5), "éé");
        assert!(display_text(&"🚀".repeat(300), 256).len() <= 256);
    }
}
