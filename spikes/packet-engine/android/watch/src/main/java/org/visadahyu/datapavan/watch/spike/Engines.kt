package org.visadahyu.datapavan.watch.spike

/**
 * The one surface every engine of the spike has (ADR 0012): start on the tunnel's descriptor, stop,
 * and the counters, in the order of `Stats::snapshot` in the Rust engine.
 */
interface PacketEngine {
    /** Takes ownership of [fd]; [service] answers owner lookups through [SpikeVpnService.ownerUid]. */
    fun start(service: SpikeVpnService, fd: Int, mtu: Int): Boolean

    fun stop()

    /** tcp flows, udp flows, bytes up, bytes down, lookups, lookup ns, unknown owners, connect errors, packets in, packets out. */
    fun stats(): LongArray
}

/** The two Rust engines, in libspike_engine.so. */
object RustEngine {
    init {
        System.loadLibrary("spike_engine")
    }

    @JvmStatic external fun nativeStart(service: Any, fd: Int, mtu: Int, kind: Int): Boolean

    @JvmStatic external fun nativeStop()

    @JvmStatic external fun nativeStats(): LongArray

    /** [kind] 0 is the userspace stack (ipstack), 1 Android's own stack through rewritten addresses. */
    fun engine(kind: Int) = object : PacketEngine {
        override fun start(service: SpikeVpnService, fd: Int, mtu: Int) = nativeStart(service, fd, mtu, kind)

        override fun stop() = nativeStop()

        override fun stats() = nativeStats()
    }
}

/** The engines by the name the measuring script passes. The Go engine joins once its AAR is built. */
val engines: Map<String, PacketEngine> = buildMap {
    put("userspace", RustEngine.engine(0))
    put("system", RustEngine.engine(1))
    GoEngine.load()?.let { put("gvisor", it) }
}

/** gomobile's binding of the gVisor engine, found by reflection so the app builds without it. */
object GoEngine {
    fun load(): PacketEngine? = try {
        val engine = Class.forName("gvisorengine.Gvisorengine")
        val start = engine.getMethod("start", Long::class.javaPrimitiveType, Long::class.javaPrimitiveType)
        val stop = engine.getMethod("stop")
        val stats = engine.getMethod("stats")
        object : PacketEngine {
            override fun start(service: SpikeVpnService, fd: Int, mtu: Int) = start.invoke(null, fd.toLong(), mtu.toLong()) as Boolean

            override fun stop() {
                stop.invoke(null)
            }

            override fun stats(): LongArray = (stats.invoke(null) as String).split(',').map { it.trim().toLong() }.toLongArray()
        }
    } catch (_: ReflectiveOperationException) {
        null
    }
}
