use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicI64, Ordering::Relaxed},
    time::Instant,
};

struct Counted;
static LIVE: AtomicI64 = AtomicI64::new(0);
unsafe impl GlobalAlloc for Counted {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Relaxed);
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as i64, Relaxed);
        System.dealloc(p, l);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let q = System.realloc(p, l, n);
        if !q.is_null() {
            LIVE.fetch_add(n as i64 - l.size() as i64, Relaxed);
        }
        q
    }
}
#[global_allocator]
static ALLOCATOR: Counted = Counted;
mod ffi {
    include!(env!("FFI_AUDIT_SOURCE"));
}
extern "C" {
    fn audit_snapshot(out: *mut u64);
}
fn c_snapshot() -> [u64; 7] {
    let mut a = [0; 7];
    unsafe { audit_snapshot(a.as_mut_ptr()) };
    a
}

// Returned Rust strings are still owned by the test. Exclude their exact live
// allocation capacities so the measured delta is leaked input ownership only.
fn check(
    label: &str,
    scenario: &str,
    old: bool,
    rust_before: i64,
    c_before: [u64; 7],
    outputs: usize,
    c_expected: u64,
    elapsed: f64,
) {
    let rust_delta = LIVE.load(Relaxed) - rust_before - outputs as i64;
    let c_after = c_snapshot();
    let inputs = c_after[5] - c_before[5];
    let c_delta = c_after[2] - c_before[2];
    assert_eq!(
        rust_delta,
        if old { inputs as i64 } else { 0 },
        "Rust ownership mismatch at {label}"
    );
    assert_eq!(
        c_delta,
        if old { c_expected } else { 0 },
        "C ownership mismatch at {label}"
    );
    println!("{{\"event\":\"ownership\",\"api\":\"{label}\",\"scenario\":\"{scenario}\",\"input_bytes\":{inputs},\"rust_leaked_bytes\":{rust_delta},\"c_leaked_bytes\":{c_delta},\"c_allocations\":{},\"c_frees\":{},\"elapsed_ms\":{elapsed}}}",c_after[3]-c_before[3],c_after[4]-c_before[4]);
}

fn generate(
    old: bool,
    json: bool,
    scenario: &str,
    a: &str,
    b: &str,
    c: &str,
    d: &str,
) -> (String, String) {
    let before = c_snapshot();
    let rust = LIVE.load(Relaxed);
    let t = Instant::now();
    let result = if json {
        ffi::generate_groth16_proof_from_json(a, b, c, d)
    } else {
        ffi::generate_groth16_proof(a, b, c, d)
    };
    check(
        if json { "generate_json" } else { "generate" },
        scenario,
        old,
        rust,
        before,
        result.0.capacity() + result.1.capacity(),
        (result.0.len() + result.1.len() + 2) as u64,
        t.elapsed().as_secs_f64() * 1000.,
    );
    result
}
fn verify(old: bool, scenario: &str, a: &str, b: &str, expected: &str) {
    let before = c_snapshot();
    let rust = LIVE.load(Relaxed);
    let t = Instant::now();
    let result = ffi::verify_groth16_proof(a, b);
    check(
        "verify",
        scenario,
        old,
        rust,
        before,
        result.capacity(),
        (result.len() + 1) as u64,
        t.elapsed().as_secs_f64() * 1000.,
    );
    assert_eq!(result, expected);
}
fn initialize(old: bool, scenario: &str, path: &str) {
    let before = c_snapshot();
    let rust = LIVE.load(Relaxed);
    let t = Instant::now();
    ffi::initialize(path);
    check(
        "initialize",
        scenario,
        old,
        rust,
        before,
        0,
        0,
        t.elapsed().as_secs_f64() * 1000.,
    );
}
fn export(old: bool, scenario: &str, path: &str, error: bool) {
    let before = c_snapshot();
    let rust = LIVE.load(Relaxed);
    let t = Instant::now();
    let result = ffi::export_solidity_verifier(path);
    check(
        "export",
        scenario,
        old,
        rust,
        before,
        result.capacity(),
        0,
        t.elapsed().as_secs_f64() * 1000.,
    );
    assert_eq!(result.starts_with("error:"), error);
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let old = args[1] == "old";
    println!("{{\"event\":\"start\",\"baseline\":{old}}}");
    if args[2] == "mock" {
        let common = "a".repeat(8192);
        let proof = "b".repeat(262144);
        let verifier = "c".repeat(65536);
        let iterations: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(1000);
        for _ in 0..iterations {
            for json in [false, true] {
                let (p, v) = generate(old, json, "mock", &common, &proof, &verifier, "keystore");
                assert_eq!(p, "proof");
                assert_eq!(v, "vk");
                let (p, v) = generate(
                    old,
                    json,
                    "mock_error",
                    "error",
                    &proof,
                    &verifier,
                    "keystore",
                );
                assert!(p.starts_with("error:"));
                assert!(v.is_empty());
            }
            verify(old, "mock", "proof", "vk", "true");
            verify(old, "mock_error", "bad", "vk", "false");
            initialize(old, "mock", "keystore");
            export(old, "mock", "keystore", false);
            export(old, "mock_error", "bad", true);
        }
        if !old {
            std::panic::set_hook(Box::new(|_| {}));
            // Null contract violations must unwind and still free non-null
            // sibling buffers. No allocation payload is printed.
            for marker in ["null_container", "null_proof", "null_vk"] {
                for json in [false, true] {
                    let c = c_snapshot();
                    assert!(std::panic::catch_unwind(|| {
                        if json {
                            ffi::generate_groth16_proof_from_json(marker, "b", "c", "d")
                        } else {
                            ffi::generate_groth16_proof(marker, "b", "c", "d")
                        }
                    })
                    .is_err());
                    assert_eq!(c_snapshot()[2], c[2]);
                }
            }
            assert!(
                std::panic::catch_unwind(|| ffi::verify_groth16_proof("null_string", "vk"))
                    .is_err()
            );
            println!("{{\"event\":\"unwind_checks_passed\",\"count\":7}}");
        }
    } else {
        let artifacts = std::path::Path::new(&args[3]);
        for (scenario, subdir) in [
            ("bridge", ""),
            ("deposit", "deposit_append"),
            ("withdrawal", "withdrawal_claim"),
        ] {
            let directory = artifacts.join("ffi").join(format!("{scenario}-00"));
            let read = |name: &str| std::fs::read_to_string(directory.join(name)).unwrap();
            let common = read("common_circuit_data.json");
            let proof = read("proof_with_public_inputs.json");
            let verifier = read("verifier_only_circuit_data.json");
            let key = artifacts.join("keystore").join(subdir);
            let key = key.to_str().unwrap();
            initialize(old, scenario, key);
            for json in [false, true] {
                let (p, v) = generate(old, json, scenario, &common, &proof, &verifier, key);
                assert!(
                    !p.starts_with("error:") && !v.is_empty(),
                    "real proof failed; payload suppressed"
                );
                verify(old, scenario, &p, &v, "true");
                println!("{{\"event\":\"proof_verified\",\"scenario\":\"{scenario}\"}}");
                let (error, vk) = generate(old, json, "invalid_input", "{", &proof, &verifier, key);
                assert!(error.starts_with("error:") && vk.is_empty());
            }
            export(old, scenario, key, false);
        }
        verify(old, "invalid_input", "{", "{", "false");
        let missing = artifacts.join("absent-ffi-audit-keystore");
        assert!(!missing.exists());
        export(old, "invalid_input", missing.to_str().unwrap(), true);
    }
    let c = c_snapshot();
    println!(
        "{{\"event\":\"finished\",\"c_live_bytes\":{},\"c_allocations\":{},\"c_frees\":{}}}",
        c[2], c[3], c[4]
    );
}
