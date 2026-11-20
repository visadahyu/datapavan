// The audit's parsers of untrusted input, which run in ParserService's isolated process (ADR 0045,
// decision 9): the DEX files and ZIP directories of other apps' APKs, and the key-attestation extension.
package org.visadahyu.datapavan.audit;

interface IParser {
    /** Loads the tracker signatures into the parser's engine; false when the engine cannot read them. */
    boolean loadSignatures(String tsv);

    /**
     * Scans one APK, given as a read-only file descriptor: its DEX files for trackers, and its entry names
     * for native libraries. Primitives only, no Bundle, so that a parser a crafted APK subverted can hand the
     * audit nothing its class loader would build (W7, part 2, fix round, security review m1): the tracker ids
     * as ApkScan.encode writes them, or null when the APK could not be read; the names of its entries under
     * lib/ are added to libraries.
     */
    int[] scanApk(in ParcelFileDescriptor apk, out List<String> libraries);

    /** The record of a KeyDescription extension (NativeCore.parseAttestation), or null when it is malformed. */
    byte[] parseAttestation(in byte[] extension);
}
