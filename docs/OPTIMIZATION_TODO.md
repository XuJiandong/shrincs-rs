# TODO: Further optimization of `sign_stateless`

Ordered from **high priority (largest impact) to low priority (incremental)**.
Impact figures are based on profiling the SHRINCS-B prepared path
(`sign_stateless_with_prepare`), which currently takes ~14 s (down from ~36 s
unprepared).

## High priority — large, real speedups (within the ~10 KiB budget)

1. **Reduce the message-dependent layer-0 XMSS cost (~13 s remaining).**
   This is the dominant residual cost for SHRINCS-B: `xmss_root` (~6.7 s) plus
   `xmss_sign` (~6.5 s) at layer 0. Its tree address is `tree_idx[0]`
   (message-derived; 4096 possible trees for B), so it cannot be precomputed
   within 10 KiB.
   - **Memoize within one signature:** the `xmss_root` call and
     `xmss_sign`'s `xmss_auth_path` for the *same* layer rebuild disjoint but
     overlapping subtrees from scratch. One shared bottom-up `treehash` pass
     for both would roughly halve layer-0 work. (Independent of the "prepare"
     file concept — pure in-signature deduplication.)
   - **Larger / probabilistic tree cache** (LRU over layer-0 trees, or a fixed
     subset of the 4096 trees): only helps if messages repeat tree indices,
     which is rare — low value, deprioritize.

2. **Memoize `treehash` across auth-path sibling subtrees (XMSS *and* PORS).**
   Each `(level, idx)` subtree in an auth path is rebuilt independently,
   re-deriving shared `wots_pk_gen`/`leaf_node` leaf work exponentially. A
   shared per-signature subtree cache collapses most of this. Directly attacks
   `pors_auth_path` (~15 s) and the residual `xmss_auth_path` cost.

3. **Profile the PORS checkpoint depth for the best speed/size tradeoff.**
   `PORS_CHECKPOINT` is fixed at height 15 (B/L) to fit an 8 KiB budget, but the
   real win depends on the octopus auth-path height distribution. A quick sweep
   could reveal a better PORS/XMSS budget split — cheap to measure, potentially
   a few more seconds saved.

## Medium priority — correctness/robustness of the cache

4. **Bind the cache to the key pair** (`pk.root`/`pk.seed` checksum in the
   header). Today a cache from a different `SecretKey` silently produces invalid
   signatures; the magic/length check guards only format, not integrity. Add a
   binding hash and have `sign_stateless_with_prepare` detect a mismatch instead
   of signing garbage.

5. **Document/encapsulate the "derived-from-`sk.seed`" nature of
   `PreparedStatelessKey`.** Fields are already private; add an explicit note
   that it is non-secret but key-bound, plus a tamper-evident checksum (pairs
   with #4).

6. **Pin `no_std` behavior.** The prepared path is `std`-only (matches existing
   signing). Confirm no downstream consumer needs a `no_std` variant before
   anyone relies on it.

## Low priority — micro / hygiene wins

7. **Perf-test all three param sets (L, B32)** for the prepared path, not just
   B. B32 shows only ~18% speedup (its shallow tree layers dominate and its PORS
   tree is small) — revisit whether the PORS/XMSS budget split should differ per
   parameter set.

8. **Allocation churn.** The hot path allocates several `Vec`s (`xof_buf`,
   `tree_idx`, `leaf_idx`, `ht_sig`, auth paths). Reuse buffers across calls
   (thread-local or caller scratch) to cut `malloc`/`memcpy` overhead — marginal
   at multi-second scales, but free.

9. **`wots_grind` / `pors_grind` thread-pool reuse.** Each call spawns
   `available_parallelism()` threads. For repeated signatures (e.g. a service),
   reusing a thread pool avoids fork/join overhead — correct but minor
   (ms vs seconds).

10. **Benchmark harness reporting.** The prepared bench case currently times
    only signing and hides the prepare cost. Add a one-time "prepare" timing
    line so the amortization break-even (prepare cost vs. per-signature savings)
    is visible when deciding whether `sign_stateless_prepare` is worthwhile.

---

**Recommended order of attack:** start with **#1** (in-signature memoization of
layer-0 root + auth path) — it is the remaining ~65 % of prepared signing time
and is self-contained, independent of the 10 KiB budget — then **#4/#5** for
production safety. Items **#2–#3** are the next meaningful speedups if pushing
further.
