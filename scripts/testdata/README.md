# Test data

`datapack-test.pub` and `datapack-test.sec` are a **public test key** for data packs, secret half
included on purpose. Debug builds trust it, so that imports can be tested (`scripts/verify-datapack.sh`,
`scripts/datapack-test.py`); release builds never do. It was made with
`signify-openbsd -G -n`, so it has no passphrase. The project's real data-signing key is kept offline
and never enters this repository; see [docs/DATA-PACKS.md](../../docs/DATA-PACKS.md).
