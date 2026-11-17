package org.visadahyu.datapavan.audit

import android.content.Context

/** Release builds log nothing of the hardware check; the debug build's lab record is in src/debug (ADR 0040). */
object AttestationLab {
    @Suppress("UNUSED_PARAMETER")
    fun recorder(context: Context): (AttestationSeen) -> Unit = { _ -> }
}
