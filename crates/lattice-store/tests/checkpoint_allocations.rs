//! Prevent checkpoint blobs becoming one heap-backed JSON Value per byte.
//! Count only allocations on this test's current thread, not SQLite workers.
use chrono::{TimeZone, Utc};
use lattice_store::{CheckpointInput, CommitInput, M2StateRepository};
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
        // SAFETY: forward the caller's exact layout to the system allocator.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        // SAFETY: forward the caller's exact layout to the system allocator.
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

#[tokio::test(flavor = "current_thread")]
async fn committing_a_large_checkpoint_does_not_materialize_json_values_per_byte() {
    let pool = lattice_store::connect_memory().await.unwrap();
    let repository = M2StateRepository::new(pool.clone());
    let bytes =
        serde_json::to_vec(&serde_json::json!({"version":1,"padding":"x".repeat(192 * 1024)}))
            .unwrap();
    let input = CommitInput {
        checkpoint: CheckpointInput {
            format_version: 1,
            bytes,
            source_fingerprint: "allocation-regression".into(),
            commit_sequence: 1,
            written_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        },
        devices: vec![],
        evidence: vec![],
        transitions: vec![],
        discovery: None,
    };
    ALLOCATED.with(|value| value.set(0));
    TRACK.with(|value| value.set(true));
    let result = repository.commit(input).await;
    TRACK.with(|value| value.set(false));
    let allocated = ALLOCATED.with(Cell::get);
    result.unwrap();
    println!("checkpoint commit allocated {allocated} bytes on its calling thread");
    // Four MiB allows serialization and SQL bookkeeping, but not a 192 KiB
    // blob expanded into one serde_json::Value object for every byte.
    assert!(
        allocated < 4 * 1024 * 1024,
        "checkpoint commit allocated {allocated} bytes"
    );
    pool.close().await;
}
