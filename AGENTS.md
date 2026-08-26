## Test

Use the following command to finish the task:

```
cargo test --release -- --skip stateless_sign_verify_all_variants
```

Don't invoke kat tests unless required. They consume a lot of time.

## ckb-debugger
The benchmark under `benchmark/ckb` requires [ckb-debugger](https://github.com/nervosnetwork/ckb-standalone-debugger) installed.
Prompt users to install it before run this benchmark. 

## Refactor
When refactoring, ensure the code matches the C++ implementation in `deps/shrincs-cpp`.
