# 0007. Direct JNI instead of UniFFI

- Status: Accepted
- Date: 2026-10-28

## Context
UniFFI generates Kotlin bindings automatically, but its Kotlin backend depends on JNA: about 1.5 MB of
extra code, plus reflection at runtime. Our JNI surface is deliberately tiny: a version call now, and
start, stop and query calls for the engine later, plus one upcall per new network flow to ask Android which
app owns it (see [VPN.md](../VPN.md)).

## Decision
Use direct JNI through the `jni` crate (0.22). Errors become Java exceptions. In debug builds,
`EnvUnowned::with_env` catches panics so they never unwind into the JVM. Release builds use
`panic = "abort"` (ADR 0006), so a panic ends the process before any unwinding.

## Consequences
- A smaller and faster app, with no reflection.
- Each export is written by hand. That is acceptable for a handful of functions, and it keeps every boundary explicit and reviewable.
- If the surface ever grows large, this decision should be revisited.
