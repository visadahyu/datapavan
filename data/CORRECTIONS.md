<!-- SPDX-License-Identifier: CC0-1.0 -->
# Corrections

Datapavan's own lists state facts about apps and the companies that make them: which tracker code an
app contains, and which signing certificates its developer uses (ADR 0015, ADR 0018). Facts can be
wrong or out of date, so anyone, the company or developer concerned included, can dispute an entry.

## How to dispute an entry

Open a public issue at https://github.com/visadahyu/datapavan/issues with:

- the dataset and the entry, for example `data/app-signers/signers.tsv`, package `org.example.app`;
- what is wrong, and what the entry should say;
- the evidence, from a source that the entry's owner controls where possible:
  - for a signing certificate, the developer's own website, repository README or release notes, a
    signed release, or an F-Droid or other repository entry;
  - for a tracker or SDK, the SDK's documentation or code, or a reproduction anyone can repeat.

Please do not send personal data from your phone. A screenshot of the app's own page in Datapavan is
enough to show what it reports.

## How it is reviewed

- A maintainer answers in the issue and checks the evidence against the primary source.
- If the entry is wrong, the fix goes into the dataset with the issue linked in the commit, and into the
  next data pack. If it is right, the issue says why, with the sources.
- A developer's own statement about its own signing keys is accepted once it is published on a channel
  it controls.

## Data that comes from elsewhere

- Tracker signatures come from the εxodus tracker database. Disputes about them go to εxodus
  (https://github.com/Exodus-Privacy/exodus), and the next import brings in the result.
- Attestation roots and the revocation list come from Google; Datapavan does not change them.
