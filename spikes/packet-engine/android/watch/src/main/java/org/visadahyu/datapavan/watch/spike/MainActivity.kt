package org.visadahyu.datapavan.watch.spike

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle

/**
 * Started by the measuring script: `--es action start --es engine userspace|system|gvisor
 * [--es allow pkg,pkg|*] [--ez quiet true]`, `--es action stats` or `--es action stop`. Asks for VPN consent the first time.
 */
class MainActivity : Activity() {
    private var pending: Intent? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handle(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    private fun handle(intent: Intent) {
        val action = intent.getStringExtra("action") ?: return
        val service = Intent(this, SpikeVpnService::class.java).putExtras(intent)
        if (action == "stop" || action == "stats") {
            startService(service.setAction(if (action == "stop") SpikeVpnService.ACTION_STOP else SpikeVpnService.ACTION_STATS))
            finish()
            return
        }
        val consent = VpnService.prepare(this)
        if (consent != null) {
            pending = service.setAction(SpikeVpnService.ACTION_START)
            @Suppress("DEPRECATION")
            startActivityForResult(consent, CONSENT)
            return
        }
        startService(service.setAction(SpikeVpnService.ACTION_START))
        finish()
    }

    @Deprecated("Activity result API is not used in the spike")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == CONSENT && resultCode == RESULT_OK) pending?.let { startService(it) }
        pending = null
        finish()
    }

    private companion object {
        const val CONSENT = 1
    }
}
