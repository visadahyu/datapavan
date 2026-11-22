// The QR decoder of a WireGuard configuration's picture, which runs in QrService's isolated process (W7, part 2;
// ADR 0035, question 10; ADR 0045, decision 9): the picture is hostile input until it is read.
package org.visadahyu.datapavan.network.tunnel.qr;

interface IQrDecoder {
    /**
     * Reads the QR code in the picture, given as a read-only file descriptor, within the bounds of QrDecode: the
     * code's text as UTF-8 bytes, or null and why in failure[0] (a QrDecode.Failure's ordinal). Primitives only, no
     * Bundle (fix round, security review m1): a decoder a hostile picture subverted can hand the network process
     * nothing that its class loader would build, as a Parcelable or Serializable value in a Bundle would be.
     */
    byte[] decode(in ParcelFileDescriptor picture, out int[] failure);
}
