// The audit's parsers of untrusted input, which run in ParserService's isolated process (ADR 0045,
// decision 9): the DEX files and ZIP directories of other apps' APKs, and the key-attestation extension.
package org.visadahyu.datapavan.audit;

interface IParser {
    /** Loads the tracker signatures into the parser's engine; false when the engine cannot read them. */
    boolean loadSignatures(String tsv);

    /**
     * Scans one APK, given as a read-only file descriptor: its DEX files for trackers, and its entry names
     * for native libraries. See ApkScan for the keys of the result.
     */
    Bundle scanApk(in ParcelFileDescriptor apk);

    /** The fields of a KeyDescription extension (NativeCore.parseAttestation), or null when it is malformed. */
    long[] parseAttestation(in byte[] extension);
}
