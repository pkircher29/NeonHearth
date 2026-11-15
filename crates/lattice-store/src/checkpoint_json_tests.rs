use super::*;
use chrono::TimeZone;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static ALLOCATED: Cell<usize> = const { Cell::new(0) };
}
struct CountingAllocator;
fn count(bytes: usize) {
    if TRACK.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCATED.try_with(|total| total.set(total.get().saturating_add(bytes)));
    }
}
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        // SAFETY: forward the caller's exact allocation to the system allocator.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        // SAFETY: forward the caller's exact allocation to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count(size);
        // SAFETY: forward the original allocation and requested size unchanged.
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forward the original allocation and layout unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn validate(bytes: &[u8]) -> Result<(), CheckpointError> {
    let at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let checksum = checkpoint_checksum_fields(1, bytes, "json-test", 1, at);
    validate_checkpoint(
        &M2StateConfig::default(),
        bytes,
        1,
        1,
        "json-test",
        "json-test",
        at,
        &checksum,
        CheckpointError::Invalid,
    )
}

fn assert_legacy_result(bytes: &[u8]) {
    let legacy = serde_json::from_slice::<serde_json::Value>(bytes);
    let actual = validate(bytes);
    match (legacy, actual) {
        (Ok(_), Ok(())) => {}
        (Err(expected), Err(CheckpointError::Invalid(actual))) => assert_eq!(
            actual,
            format!("checkpoint bytes are not JSON: {expected}"),
            "input: {bytes:?}"
        ),
        (expected, actual) => {
            panic!("validation differs for {bytes:?}: legacy {expected:?}, actual {actual:?}")
        }
    }
}

#[test]
fn checkpoint_json_validation_matches_value_parser() {
    let cases = [
        "null",
        "true",
        "false",
        "0",
        "-0",
        "1.25",
        "1e-400",
        "1e400",
        "-1e400",
        "18446744073709551615",
        "18446744073709551616",
        "-9223372036854775809",
        "[]",
        "{}",
        "[null,true,false,1,-2,3.5]",
        "{\"a\":1,\"a\":2}",
        "{\"a\":1,\"a\":1e400}",
        "{\"1e400\":1}",
        "{\"\":[]}\n\t ",
        "\"Café 日本語 🏠\"",
        "\"\\uD83C\\uDFE0\\n\\\"\\\\\"",
        "{\"\\u0061\":{\"é\":[\"\\u0000\"]}}",
        "",
        " ",
        "nul",
        "null false",
        "{}[]",
        "[1,]",
        "{\"a\":}",
        "{1:2}",
        "{\"a\":1,}",
        "\"\\uD800\"",
        "\"\\uDC00\"",
        "\"\\uZZZZ\"",
        "\"\\x\"",
        "\"\n\"",
        "[",
        "{",
        "01",
        "+1",
        "1.",
        "1e",
        "NaN",
        "Infinity",
    ];
    for text in cases {
        assert_legacy_result(text.as_bytes());
    }
    for bytes in [vec![b'"', 0xff, b'"'], vec![b'[', b'0', 0, b']']] {
        assert_legacy_result(&bytes);
    }
    for depth in [1, 64, 126, 127, 128, 129, 256] {
        for (open, close) in [("[", "]"), ("{\"a\":", "}")] {
            assert_legacy_result(
                format!("{}0{}", open.repeat(depth), close.repeat(depth)).as_bytes(),
            );
        }
    }
    // Corrupt every byte and truncate every prefix of a mixed document. Both
    // parsers must reject malformed UTF-8/escapes, separators and trailing data alike.
    let document = r#"{"a":[1,true,null,{"é":"\uD83C\uDFE0"}],"a":-2.5e30}"#.as_bytes();
    for i in 0..document.len() {
        assert_legacy_result(&document[..i]);
        for replacement in [0, b'"', b']', b'0', 0xff] {
            let mut altered = document.to_vec();
            altered[i] = replacement;
            assert_legacy_result(&altered);
        }
    }
}

fn large_document() -> Vec<u8> {
    format!(
        "[{}]",
        r#"{"a":[1,true,null],"b":"Café"},"#.repeat(16_384).trim_end_matches(',')
    )
    .into_bytes()
}

#[test]
fn checkpoint_json_validation_does_not_allocate_a_value_tree() {
    let bytes = large_document();
    let at = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let checksum = checkpoint_checksum_fields(1, &bytes, "allocation-test", 1, at);
    ALLOCATED.with(|value| value.set(0));
    TRACK.with(|value| value.set(true));
    let result = validate_checkpoint(
        &M2StateConfig::default(),
        &bytes,
        1,
        1,
        "allocation-test",
        "allocation-test",
        at,
        &checksum,
        CheckpointError::Invalid,
    );
    TRACK.with(|value| value.set(false));
    let allocated = ALLOCATED.with(Cell::get);
    result.unwrap();
    println!(
        "{}-byte checkpoint validation allocated {allocated} bytes",
        bytes.len()
    );
    // A generous allowance for parser scratch/checksum bookkeeping, independent
    // of object count. A Value tree for this fixture allocates many MiB.
    assert!(
        allocated < 64 * 1024,
        "validation allocated {allocated} bytes"
    );
}

#[test]
fn checkpoint_json_validation_microbenchmark() {
    let bytes = large_document();
    let start = std::time::Instant::now();
    for _ in 0..8 {
        std::hint::black_box(
            serde_json::from_slice::<serde_json::Value>(std::hint::black_box(&bytes)).unwrap(),
        );
    }
    let legacy = start.elapsed();
    let start = std::time::Instant::now();
    for _ in 0..8 {
        std::hint::black_box(serde_json::from_slice::<JsonSyntax>(std::hint::black_box(
            &bytes,
        )))
        .unwrap();
    }
    println!(
        "8x {}-byte JSON: Value parse {legacy:?}, syntax parse {:?}",
        bytes.len(),
        start.elapsed()
    );
}
