# test-shrincs

A `no_std` RISC-V CKB contract that verifies a
[SHRINCS](../../../../README.md) post-quantum signature inside the CKB VM.

It is the core of the on-chain benchmark in [`benchmark/ckb`](../..), executed
locally with `ckb-debugger`:

```sh
ckb-debugger --bin <path-to-elf> <message> <signature> <pubkey>
```

## Behavior

`program_entry` (see `src/main.rs`):

1. Initializes logging via ckb-std's `log` feature (`ckb_std::logger::init`),
   so each run prints `Script log:` lines under `ckb-debugger`.
2. Reads argv: `[program?,] message, signature, pubkey`. Both layouts are
   accepted — `ckb-debugger --bin` passes exactly the three values
   (`argv[0..3]`), but a four-element argv with a program name at `argv[0]`
   also works.
3. Hex-decodes each argument.
4. Parses the 32-byte pubkey as `seed (16) ‖ root (16)`.
5. Calls `shrincs::verify::<SHRINCS_B>` — the no_std verification path of
   shrincs-rs (linked with `default-features = false`). The signature family
   (stateful vs stateless) is dispatched from the signature length; the
   stateful tree root and counter `q` are both derived from the signature, so
   no state argument is needed.
6. Returns `0` on success, `1` on verification failure, and a small non-zero
   code on argument/decoding errors.

The compiled parameter set is `SHRINCS_B` (configurable via the
`CurrentParams` type alias in `src/main.rs`).

## Build

From `benchmark/ckb`, run:

```sh
make build    # -> build/release/test-shrincs (ELF + .debug copy)
```

The argument generator and end-to-end benchmark commands are documented in the
parent [`benchmark/ckb/README.md`](../../README.md).

*This contract was bootstrapped with [ckb-script-templates].*

[ckb-script-templates]: https://github.com/nervosnetwork/ckb-script-templates