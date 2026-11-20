//! Skipped rule blocks must not allocate copies of their immutable metadata.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use zentinel_modsec::ModSecurity;

thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

fn count_allocation() {
    let _ = TRACKING.try_with(|enabled| {
        if enabled.get() {
            let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        }
    });
}

// SAFETY: every operation delegates unchanged to the system allocator; the
// thread-local counters neither allocate nor inspect allocated memory.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count_allocation();
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn rules(skipped: usize) -> ModSecurity {
    let mut config = String::from(
        "SecRuleEngine DetectionOnly\n\
         SecRule REQUEST_METHOD \"@streq GET\" \"id:1,phase:2,pass,skipAfter:END\"\n",
    );
    for i in 0..skipped {
        config.push_str(&format!(
            "SecRule ARGS \"@contains secret\" \"id:{},phase:2,pass,t:lowercase,msg:'inactive rule metadata',tag:'paranoia-level/4'\"\n",
            i + 100
        ));
    }
    config.push_str(
        "SecMarker END\n\
         SecRule REQUEST_METHOD \"@streq GET\" \"id:999999,phase:2,pass\"\n",
    );
    ModSecurity::from_string(&config).unwrap()
}

fn request_allocations(engine: &ModSecurity) -> (usize, Vec<String>) {
    ALLOCATIONS.set(0);
    TRACKING.set(true);
    let mut tx = engine.new_transaction();
    tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    TRACKING.set(false);
    let allocations = ALLOCATIONS.get();
    (allocations, tx.matched_rules().to_vec())
}

#[test]
fn inactive_rule_blocks_have_bounded_request_allocation_cost() {
    let small = rules(1);
    let large = rules(200);
    // Keep loader/lazy initialization outside the measured request windows.
    request_allocations(&small);
    request_allocations(&large);
    let (small_count, small_matches) = request_allocations(&small);
    let (large_count, large_matches) = request_allocations(&large);
    assert_eq!(small_matches, ["1", "999999"]);
    assert_eq!(large_matches, small_matches);
    // The slack permits small fixed bookkeeping changes, while catching the
    // thousands of allocations caused by copying a skipped rule block.
    assert!(
        large_count <= small_count + 64,
        "skipped metadata caused per-request allocation growth: {small_count} -> {large_count}"
    );
}
