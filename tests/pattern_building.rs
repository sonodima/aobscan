#[test]
fn ida_pattern() {
    assert!(
        // Valid IDA pattern (mix of ? and ?? is allowed)
        aobscan::PatternBuilder::from_ida_style("48 8B ?? ?").is_ok()
    );

    assert!(
        // Valid IDA pattern (spaces are not considered)
        aobscan::PatternBuilder::from_ida_style("48 8B  48 8B 88").is_ok()
    );

    assert!(
        // Valid IDA pattern (one-char patterns are allowed)
        aobscan::PatternBuilder::from_ida_style("A").is_ok()
    );

    assert!(
        // Invalid IDA pattern (empty pattern)
        aobscan::PatternBuilder::from_ida_style("").is_err()
    );

    assert!(
        // Invalid IDA pattern (invalid byte)
        aobscan::PatternBuilder::from_ida_style("48 8B ? ? 48 8B 88 ? ? ? ZA").is_err()
    );

    assert!(
        // Invalid IDA pattern (invalid wildcard length)
        aobscan::PatternBuilder::from_ida_style("48 8B ? ? 48 8B 88 ? ? ???").is_err()
    );

    assert!(
        // Valid IDA pattern (signatures without static bytes are allowed, but pointless)
        aobscan::PatternBuilder::from_ida_style("?? ?? ?? ??").is_ok()
    );
}

#[test]
fn code_pattern() {
    // Code patterns are usually pretty safe, so we don't need to test them as much.

    assert!(
        // Valid code pattern
        aobscan::PatternBuilder::from_code_style(b"\x48\x8B\x00\x00", "..??").is_ok()
    );

    assert!(
        // Invalid code pattern (length of pattern and mask don't match)
        aobscan::PatternBuilder::from_code_style(b"\x48\x8B\x00\x00", "...??").is_err()
    );
}

#[test]
fn hex_pattern() {
    assert!(
        // Valid hex pattern
        aobscan::PatternBuilder::from_hex_string("488b????").is_ok()
    );

    assert!(
        // Valid hex pattern (signatures without static bytes are allowed, but pointless)
        aobscan::PatternBuilder::from_hex_string("????").is_ok()
    );

    assert!(
        // Invalid hex pattern (invalid byte)
        aobscan::PatternBuilder::from_hex_string("488b????ZA").is_err()
    );

    assert!(
        // Invalid hex pattern (single char wildcard)
        aobscan::PatternBuilder::from_hex_string("488b???b").is_err()
    );

    assert!(
        // Invalid hex pattern (length of pattern is not a multiple of 2)
        aobscan::PatternBuilder::from_hex_string("488b0f3").is_err()
    );

    assert!(
        // Invalid hex pattern (empty pattern)
        aobscan::PatternBuilder::from_hex_string("").is_err()
    );

    assert!(
        // Invalid hex pattern (empty pattern)
        aobscan::PatternBuilder::from_hex_string(" ").is_err()
    );

    assert!(
        // Invalid hex pattern (single-char wildcard)
        aobscan::PatternBuilder::from_hex_string("?").is_err()
    );
}
