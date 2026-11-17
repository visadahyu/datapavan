package org.visadahyu.datapavan.audit

/** Release builds log nothing of the hardware check; the debug build's lab record is in src/debug (ADR 0040). */
object AttestationLab {
    @Suppress("UNUSED_PARAMETER")
    fun record(seen: AttestationSeen) = Unit
}
