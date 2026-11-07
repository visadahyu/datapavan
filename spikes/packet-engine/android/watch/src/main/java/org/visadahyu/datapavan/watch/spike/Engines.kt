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

/** The engines by the name the measuring script passes. */
val engines: Map<String, PacketEngine> = mapOf(
    "userspace" to RustEngine.engine(0),
    "system" to RustEngine.engine(1),
    "gvisor" to GoEngine,
)

/** gomobile's binding of the gVisor engine in ../go: `gvisorengine.Gvisorengine`. */
object GoEngine : PacketEngine {
    override fun start(service: SpikeVpnService, fd: Int, mtu: Int): Boolean =
        gvisorengine.Gvisorengine.start(fd.toLong(), mtu.toLong()) { protocol, source, sourcePort, destination, destinationPort ->
            service.ownerUid(protocol, source, sourcePort, destination, destinationPort)
        }

    override fun stop() = gvisorengine.Gvisorengine.stop()

    override fun stats(): LongArray = gvisorengine.Gvisorengine.stats().split(',').map { it.trim().toLong() }.toLongArray()
}
