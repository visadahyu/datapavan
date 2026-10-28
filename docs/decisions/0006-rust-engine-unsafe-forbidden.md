# 0006. Rust engine with `unsafe` forbidden; separate JNI crate

- Status: Accepted
- Date: 2026-10-28

## Context
The engine parses hostile input: packets from every app and server (v0.2), and DEX files from other
apps (v0.1). In C or C++, a parser bug in this position becomes a remote exploit on the user's phone.
The same engine must also serve stage 2 (Device Owner) and stage 3 (a system service in our OS).

## Decision
- All logic lives in `datapavan-engine`. The workspace lint `unsafe_code = "forbid"` makes the compiler reject any `unsafe`.
- `datapavan-jni` is a thin bridge, and the only crate allowed `unsafe`. Every unsafe block needs a `// SAFETY:` comment (Clippy `undocumented_unsafe_blocks = deny`).
- Release builds are size-optimised (`opt-level = "s"`, fat LTO, one codegen unit, `panic = "abort"`, stripped).

## Consequences
- Memory-safety bugs in parsers are ruled out by construction; the remaining risk is logic bugs, which fuzzing targets.
- The engine is portable across all three stages.
- `panic = "abort"`: a panic crashes the app instead of continuing in an unknown state. The VPN lockdown mode then fails closed (see [VPN.md](../VPN.md)).
