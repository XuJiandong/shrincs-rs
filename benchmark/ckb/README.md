# SHRINCS on CKB: on-chain verification benchmark

This benchmark measures the cost of verifying a
[SHRINCS](../../README.md) post-quantum signature inside the CKB VM. The
contract runs on RISC-V (`riscv64imac-unknown-none-elf`, `no_std`) and is
executed offline with [`ckb-debugger`](https://github.com/nervosnetwork/ckb-standalone-debugger/blob/develop/ckb-debugger/guide.md),
so no CKB node or transaction is required.

## Layout

* `contracts/test-shrincs` — the on-chain verifier contract. It parses the
  three hex arguments `message`, `signature`, `pubkey` from argv and calls
  `shrincs::verify` (the no_std verification path of shrincs-rs).
  Stateful vs stateless is dispatched automatically from the signature length.
* `tools/gen-args` — a host-side (`std`) command-line tool that generates the
  three arguments for **both** signature families (stateful with configurable
  counter `q`, and stateless) from a fixed master seed, so runs are
  reproducible.
* `scripts/` — build helpers from the ckb script template.

## Build & run

Prerequisites: a Rust toolchain with the `riscv64imac-unknown-none-elf`
target, `clang` (for the C build helper), and `ckb-debugger` in `PATH`.

```sh
make build          # build the RISC-V contract -> build/release/test-shrincs
make gen-args       # build the host-side argument generator
make bench          # run stateful (q=1) and stateless verification, report cycles
```

`ckb-debugger` prints the verification logs (`Script log:` lines, enabled via
ckb-std's `log` feature) and the exit code:

* `Run result: 0` — signature verified.
* `Run result: 1` — signature rejected (verify returned `false`).
* Other codes — argument/parsing error.

Examples:

```sh
# One specific generated argument set:
make bench-repr GEN_ARGS="--stateless"
make bench-repr GEN_ARGS="--param L --stateful --q 3"

# Or run ckb-debugger directly with generated args:
args=$(./target/release/gen-shrincs-args --stateful --q 1)
ckb-debugger --bin build/release/test-shrincs $args
```

## Argument format

`tools/gen-args` emits one line of three space-separated hex strings:

```
<message> <signature> <pubkey>
```

This is exactly the argv consumed by the contract:

1. `message` — arbitrary bytes.
2. `signature` — either a stateful signature (`sl` prefix, short, length
   depends on the counter `q`) or a stateless signature (`sf` prefix, long,
   fixed length per parameter set).
3. `pubkey` — 32 bytes: public `seed (16) ‖ root (16)`.

Note that SHRINCS verification is self-contained: the stateful tree root and
the counter `q` are both derived from the signature itself (the `sl` prefix and
the authentication-path length), so no state argument is needed.

```
USAGE of tools/gen-args:
  gen-shrincs-args [--param B|B32|L] [--stateful|--stateless] [--q N]
                   [--seed <48-byte hex>] [--msg-hex <hex>]
```

*This project was bootstrapped with [ckb-script-templates].*

[ckb-script-templates]: https://github.com/nervosnetwork/ckb-script-templates