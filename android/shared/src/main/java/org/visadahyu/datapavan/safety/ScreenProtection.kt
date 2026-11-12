package org.visadahyu.datapavan.safety

import android.os.Build
import android.os.Handler
import android.os.Looper
import android.view.Window
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Both apps protect every screen (ADR 0040, decision 1), as Molly does for people at risk. Screenshots
 * and screen recordings show a black window and the app is blank in the recent apps, so what Datapavan
 * shows does not end up in a gallery, a cloud backup or someone else's recording. From Android 12 the
 * apps also hide other apps' overlays from their own windows, so that an app drawn over Datapavan
 * cannot dress its screens or read them.
 *
 * A person who needs a screenshot to ask for help lifts the protection for [LIFT_MS]. It comes back by
 * itself then, or as soon as the app starts to leave the screen, whichever comes first.
 */
object ScreenProtection {
    /** How long screenshots stay allowed after the user allows them. */
    const val LIFT_MS = 60_000L

    private val handler = Handler(Looper.getMainLooper())
    private val liftedFlow = MutableStateFlow(false)
    private var window: Window? = null
    private var neverProtect = false
    private val restore = Runnable { protect() }

    /** Whether screenshots are allowed now, for the setting's text and button. */
    val lifted: StateFlow<Boolean> = liftedFlow.asStateFlow()

    /**
     * Protects [activity]'s window from now on, and ends any lift when it leaves the screen. Call it
     * from onCreate. [screenshotsForTests] keeps the window unprotected: debug builds only, for the
     * scripts that take the store's and the accessibility check's screenshots (scripts/screenshots.sh).
     */
    fun attach(activity: ComponentActivity, screenshotsForTests: Boolean) {
        window = activity.window
        neverProtect = screenshotsForTests
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            activity.window.setHideOverlayWindows(true)
        }
        protect()
        activity.lifecycle.addObserver(
            object : DefaultLifecycleObserver {
                // From the first moment the app starts to leave the screen: before Android takes the
                // recent apps' thumbnail, and also when the app comes back before it was stopped.
                override fun onPause(owner: LifecycleOwner) = protect()

                override fun onStop(owner: LifecycleOwner) = protect()

                override fun onDestroy(owner: LifecycleOwner) {
                    if (window === activity.window) window = null
                }
            },
        )
    }

    /** Allows screenshots for [LIFT_MS], or until the app leaves the screen. */
    fun lift() {
        handler.removeCallbacks(restore)
        liftedFlow.value = true
        window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        handler.postDelayed(restore, LIFT_MS)
    }

    /** Protects the screen again, now. */
    fun protect() {
        handler.removeCallbacks(restore)
        liftedFlow.value = false
        val window = window ?: return
        if (neverProtect) {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}
