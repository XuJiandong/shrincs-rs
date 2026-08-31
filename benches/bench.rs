//! Native Rust benchmark for the SHRINCS implementation, mirroring
//! [`deps/shrincs-cpp/tests/bench.cpp`](../deps/shrincs-cpp/tests/bench.cpp).
//!
//! Five cases are measured, the first four in the same order as the C++ bench:
//!
//!   1. stateful signing
//!   2. stateful verification
//!   3. stateless signing
//!   4. stateless verification
//!   5. stateless signing (prepared)
//!
//! Key generation is preparation work only: it runs once, before any timer is
//! started, and is never part of a timed region. Similarly, the stateless
//! "prepare" cache (see `sign_stateless_prepare`) is built once per key pair
//! and is not part of the timed signing regions; only the prepared signing
//! itself is timed.
//!
//! # Usage
//!
//! ```text
//! cargo bench --bench bench                    # SHRINCS_B (recommended default), 1 call each
//! cargo bench --bench bench -- --param B32 --iters 8   # avg over 8 calls, SHRINCS_B32
//! cargo bench --bench bench -- --param L --iters 16    # avg over 16 calls, SHRINCS_L
//! ```
//!
//! (`cargo bench` also benches the library unit tests, which reject unknown
//! arguments, so select the target with `--bench bench`.)
//!
//! `--param` accepts `B`, `L`, or `B32` and defaults to `B`, the crate's
//! recommended parameter set (smallest signature size).
//! `--iters N` repeats each case N times (default 1, exactly like the C++
//! single-shot bench) and reports total/min/avg/max. Stateful signing advances
//! `state.q` across iterations, so `--iters` is capped at `HSF + 1`.

use std::env;
use std::hint::black_box;
use std::time::{Duration, Instant};

use shrincs_rs::{
    Params, PublicKey, SHRINCS_B, SHRINCS_B32, SHRINCS_L, SecretKey, State, key_gen, sign_stateful,
    sign_stateless, sign_stateless_prepare, sign_stateless_with_prepare, verify,
};

fn main() {
    // Matches the crate's recommended default parameter set (SHRINCS_B).
    let mut param = String::from("B");
    let mut iters = 1usize;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        // `cargo bench` injects `--bench` into harness = false bench
        // executables; it is a cargo control argument, not a real flag.
        if arg == "--bench" {
            continue;
        }
        match arg.as_str() {
            "--param" => {
                param = args
                    .next()
                    .expect("--param requires a value (B, L, or B32)")
                    .to_owned();
            }
            "--iters" => {
                iters = args
                    .next()
                    .expect("--iters requires a value")
                    .parse()
                    .expect("--iters must be a positive integer");
            }
            "--help" | "-h" => {
                println!(
                    "usage: bench [--param B|L|B32] [--iters N]\n\n\
                     Defaults: --param B (recommended parameter set), --iters 1."
                );
                return;
            }
            other => panic!("unknown argument: {other}"),
        }
    }
    assert!(iters >= 1, "--iters must be >= 1");

    match param.as_str() {
        "B" => run::<SHRINCS_B>("B", iters),
        "L" => run::<SHRINCS_L>("L", iters),
        "B32" => run::<SHRINCS_B32>("B32", iters),
        other => panic!("unknown parameter set: {other} (expected B, L, or B32)"),
    }
}

fn run<P: Params>(param: &str, iters: usize) {
    assert!(
        iters <= P::HSF + 1,
        "--iters {iters} exceeds the stateful limit HSF + 1 = {} for params {param}",
        P::HSF + 1
    );

    let mut pk = PublicKey::default();
    let mut sk = SecretKey::default();
    let mut state = State::default();

    // Key generation is preparation work only: it is not part of the benchmark.
    key_gen::<P>(&mut pk, &mut sk, &mut state).unwrap();

    // Same message as the C++ bench: 32 zero bytes.
    let message = [0u8; 32];

    println!("== SHRINCS-{param} (key generation excluded from all timings) ==\n");

    let mut sig = Vec::new();

    // 1. Stateful signing
    bench_batch(&format!("Stateful signing [{param}]"), iters, || {
        sig = sign_stateful::<P>(&message, &mut sk, &mut state).unwrap();
        black_box(&sig);
    });

    // 2. Stateful verification
    bench_batch(&format!("Stateful verification [{param}]"), iters, || {
        let ok = verify::<P>(&message, &sig, &pk);
        assert!(ok, "stateful verification failed");
        black_box(ok);
    });

    // 3. Stateless signing
    bench_batch(&format!("Stateless signing [{param}]"), iters, || {
        sig = sign_stateless::<P>(&message, &sk).unwrap();
        black_box(&sig);
    });

    // 4. Stateless verification
    bench_batch(&format!("Stateless verification [{param}]"), iters, || {
        let ok = verify::<P>(&message, &sig, &pk);
        assert!(ok, "stateless verification failed");
        black_box(ok);
    });

    // 5. Stateless signing with a precomputed cache. Building the cache is
    //    preparation work (done once per key pair), so it is timed separately
    //    and excluded from the signing figure.
    let prepared = sign_stateless_prepare::<P>(&sk);
    bench_batch(
        &format!("Stateless signing (prepared) [{param}]"),
        iters,
        || {
            sig = sign_stateless_with_prepare::<P>(&message, &sk, &prepared).unwrap();
            black_box(&sig);
        },
    );

    println!();
    println!(
        "stateful counter ended at q = {} ({} stateful signatures produced)",
        state.q, state.q
    );
}

/// Run `op` `iters` times, timing each call, and print total/min/avg/max.
fn bench_batch(label: &str, iters: usize, mut op: impl FnMut()) {
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        op();
        samples.push(start.elapsed());
    }

    let total: Duration = samples.iter().copied().sum();
    let min = samples.iter().copied().min().unwrap_or_default();
    let max = samples.iter().copied().max().unwrap_or_default();
    let avg = total / iters as u32;

    if iters == 1 {
        println!("{label} time: {:.3} ms", ms(total));
    } else {
        println!(
            "{label} time: {:.3} ms (avg of {iters} calls; min {:.3} ms, max {:.3} ms)",
            ms(avg),
            ms(min),
            ms(max)
        );
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}
