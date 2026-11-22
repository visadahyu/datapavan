package org.visadahyu.datapavan.network.tunnel

import java.io.IOException
import java.security.GeneralSecurityException
import java.security.ProviderException

/**
 * A change of the configurations' store from Watch's screen, run on the store's worker (W7, part 2, fix round,
 * security review M3). Whatever the store throws, a full disk, a Keystore error, or a slot removed while the
 * confirmation was open, ends that change alone, never Watch's process, which carries the VPN: until Android
 * started it again, every app would go outside Watch. The store's changes are all or nothing ([TunnelStore]), so it
 * is left as it was, and the screen says in plain words that nothing was saved, and why where that is known.
 */
object Changes {
    /** Why a change was not saved. */
    enum class NotSaved {
        /** The disk could not be written, as when it is full. */
        STORAGE,

        /** The Keystore did not wrap. */
        KEYSTORE,

        /** The configuration the change names was removed meanwhile. */
        GONE,

        /** The engine's bound of configurations is reached. */
        FULL,

        /** Anything else. */
        OTHER,
    }

    /** Runs [change]; null when it was saved, else why not. */
    fun run(change: () -> Unit): NotSaved? = try {
        change()
        null
    } catch (e: Exception) {
        why(e)
    }

    fun why(e: Exception): NotSaved = when (e) {
        is TunnelStore.SlotGone -> NotSaved.GONE
        is IOException -> NotSaved.STORAGE
        is GeneralSecurityException, is ProviderException -> NotSaved.KEYSTORE
        else -> NotSaved.OTHER
    }

    /** What saving the import's confirmation came to. */
    sealed interface Saved {
        data class Added(val slot: Int) : Saved
        data class Replaced(val slot: Int) : Saved
        data class Not(val why: NotSaved) : Saved
    }

    /**
     * Saves the confirmed configuration [pending], whose bytes are zeroed whatever happens: in place of the slot
     * [replacing], its apps and switches kept, or as a new one with [name], "Local network directly" as [local] and
     * the [apps] chosen for it, in one change of the store.
     */
    fun save(store: TunnelStore, pending: Import.Pending, name: String, replacing: Int?, local: Boolean, apps: Set<String>): Saved =
        try {
            val text = pending.text ?: return Saved.Not(NotSaved.OTHER)
            if (replacing != null) {
                store.replace(replacing, text, name)
                Saved.Replaced(replacing)
            } else {
                store.add(name, text, local, apps)?.let { Saved.Added(it) } ?: Saved.Not(NotSaved.FULL)
            }
        } catch (e: Exception) {
            Saved.Not(why(e))
        } finally {
            pending.close()
        }
}
