// The QR decoder of a WireGuard configuration's picture, which runs in QrService's isolated process (W7, part 2;
// ADR 0035, question 10; ADR 0045, decision 9): the picture is hostile input until it is read.
package org.visadahyu.datapavan.watch.tunnel.qr;

interface IQrDecoder {
    /**
     * Reads the QR code in the picture, given as a read-only file descriptor, within the bounds of QrDecode: the
     * code's text as UTF-8 bytes under "text", or why not under "failure" (QrDecode.Failure's names).
     */
    Bundle decode(in ParcelFileDescriptor picture);
}
