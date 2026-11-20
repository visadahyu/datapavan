package org.visadahyu.datapavan.watch.tunnel

import android.content.res.Resources
import org.visadahyu.datapavan.ui.isolateLtr
import org.visadahyu.datapavan.watch.R
import org.visadahyu.datapavan.watch.tunnel.qr.QrDecode

/**
 * Why a configuration was refused, in plain words (W7, part 2): each code the engine's parser gives (core/net's
 * `Refusal::code`) and the bridge's own (`too-many`), with its line and key where it names them; never a value,
 * which the engine never gives. A test fails when a code has no words here ([RefusalsTest]).
 */
object Refusals {
    /** The words for [code], or null for one the engine never gives. */
    fun of(code: String): Int? = when (code) {
        "too-long" -> R.string.refused_too_long
        "not-text" -> R.string.refused_not_text
        "unreadable" -> R.string.refused_unreadable
        "outside-section" -> R.string.refused_outside_section
        "unknown-section" -> R.string.refused_unknown_section
        "several-interfaces" -> R.string.refused_several_interfaces
        "several-peers" -> R.string.refused_several_peers
        "unsupported" -> R.string.refused_unsupported
        "repeated" -> R.string.refused_repeated
        "bad-value" -> R.string.refused_bad_value
        "several-addresses" -> R.string.refused_several_addresses
        "search-domain" -> R.string.refused_search_domain
        "no-interface" -> R.string.refused_no_interface
        "no-peer" -> R.string.refused_no_peer
        "no-private-key" -> R.string.refused_no_private_key
        "no-address" -> R.string.refused_no_address
        "no-dns" -> R.string.refused_no_dns
        "dns-unreachable" -> R.string.refused_dns_unreachable
        "no-public-key" -> R.string.refused_no_public_key
        "no-endpoint" -> R.string.refused_no_endpoint
        "no-allowed-ips" -> R.string.refused_no_allowed_ips
        "bad-mtu" -> R.string.refused_bad_mtu
        "both-application-lists" -> R.string.refused_both_application_lists
        // A plural, with the engine's bound (fix round, screens review m8).
        "too-many" -> R.plurals.refused_too_many
        else -> null
    }

    /** The codes whose words name the key, as `%1$s`. */
    private val NAMING = setOf("unsupported", "repeated", "bad-value")

    /** The refusal in words, with its line first where it has one. */
    fun words(resources: Resources, refused: Import.Refused): String {
        val id = of(refused.code) ?: return resources.getString(R.string.refused_unknown)
        val key = refused.key?.let(::isolateLtr)
        val text = when {
            refused.code == "too-many" -> resources.getQuantityString(id, TunnelStore.MAX, TunnelStore.MAX)
            refused.code !in NAMING -> resources.getString(id)
            key != null -> resources.getString(id, key)
            refused.code == "unsupported" -> resources.getString(R.string.refused_unsupported_unnamed)
            else -> resources.getString(R.string.refused_unknown)
        }
        return refused.line?.let { resources.getString(R.string.refused_line, it, text) } ?: text
    }

    /**
     * Why a change of the configurations was not saved, in plain words (fix round, security review M3): the words'
     * resource, a plural for the engine's bound alone.
     */
    fun of(why: Changes.NotSaved): Int = when (why) {
        Changes.NotSaved.STORAGE -> R.string.tunnels_not_saved_storage
        Changes.NotSaved.KEYSTORE -> R.string.tunnels_not_saved_keystore
        Changes.NotSaved.GONE -> R.string.tunnels_not_saved_gone
        Changes.NotSaved.FULL -> R.plurals.refused_too_many
        Changes.NotSaved.OTHER -> R.string.tunnels_not_saved_other
    }

    fun words(resources: Resources, why: Changes.NotSaved): String = when (why) {
        Changes.NotSaved.FULL -> words(resources, Import.Refused("too-many"))
        else -> resources.getString(of(why))
    }

    /** Why a picture gave no configuration, in plain words. */
    fun of(failure: QrDecode.Failure): Int = when (failure) {
        QrDecode.Failure.NOT_A_PICTURE -> R.string.qr_not_a_picture
        QrDecode.Failure.TOO_LARGE -> R.string.qr_too_large
        QrDecode.Failure.NO_CODE -> R.string.qr_no_code
        QrDecode.Failure.TOO_LONG -> R.string.qr_too_long
        QrDecode.Failure.TOO_SLOW -> R.string.qr_too_slow
        QrDecode.Failure.STOPPED -> R.string.qr_stopped
    }
}
