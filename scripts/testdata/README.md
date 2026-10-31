# Test data

`datapack-test.pub` and `datapack-test.sec` are a **public test key** for data packs, secret half
included on purpose. Debug builds trust it, so that imports can be tested (`scripts/verify-datapack.sh`,
`scripts/datapack-test.py`); release builds never do. It was made with
`signify-openbsd -G -n`, so it has no passphrase. The project's real data-signing key is kept offline
and never enters this repository; see [docs/DATA-PACKS.md](../../docs/DATA-PACKS.md).

`aosp-platform.pk8` and `aosp-platform.x509.pem` are AOSP's **public platform test key**
(`build/make/target/product/security/platform.*` in the Android Open Source Project, Apache-2.0,
downloaded 2026-10-31; certificate SHA-256 `c8a2e9bc…192ab8`, serial `b3998086d056cffa`). Any phone
that trusts this key as its platform key trusts code that anyone can sign. `scripts/verify-audit.sh`
signs the test fixture with it, so that Datapavan must report an app signed with a public system key
(ADR 0023).
