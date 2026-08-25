Rewrite project at ~/projects/shrincs-cpp from C++ to Rust.

* Only support little-endian platforms, as the target platform is little-endian.
* Support SHRINCS_L, SHRINCS_B, and SHRINCS_B32, which can coexist without conflicting.
* Clearly document every parameter, such as W, L, and D.
* The verification part should support no_std.
* The signing part should support std.
* Keep the same Rust module names as the C++ file names (for example, uxmss, wots_c, pors_fp, hash).
* Choose third-party crates carefully. Must use https://crates.io/crates/ckb-opt-sha256 for SHA-256 functions.
* the tests under `kat/` should be passed.
* the tests under `tests/` should be included

