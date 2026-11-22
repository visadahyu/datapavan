package org.visadahyu.datapavan.watch

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test
import java.io.File
import java.net.InetAddress

class TunnelAddressesTest {
    private fun ip(text: String): InetAddress = InetAddress.getByName(text)

    private fun network(address: String, prefix: Int, vararg others: String) =
        TunnelAddresses.Network(listOf(ip(address) to prefix), others.map(::ip))

    @Test
    fun theCommonAddressesUnlessTheNetworkUsesThem() {
        assertSame("no network yet", TunnelAddresses.COMMON, TunnelAddresses.choose(emptyList()))
        assertSame(
            "a home network",
            TunnelAddresses.COMMON,
            TunnelAddresses.choose(listOf(network("192.168.1.23", 24, "192.168.1.1"))),
        )
        assertSame(
            "a Comcast Business gateway's network: the router answers at 10.1.10.1",
            TunnelAddresses.SPARE,
            TunnelAddresses.choose(listOf(network("10.1.10.57", 24, "10.1.10.1"))),
        )
        assertSame(
            "a resolver at the common DNS address, on another subnet",
            TunnelAddresses.SPARE,
            TunnelAddresses.choose(listOf(network("172.16.4.9", 22, "10.1.10.3"))),
        )
        assertSame(
            "an IPv6 network whose prefix holds the common IPv6 address",
            TunnelAddresses.SPARE,
            TunnelAddresses.choose(listOf(network("fd00:1:fd00:1::77", 64))),
        )
        assertSame(
            "a neighbouring subnet is no clash",
            TunnelAddresses.COMMON,
            TunnelAddresses.choose(listOf(network("10.1.11.5", 24, "10.1.11.1"))),
        )
        assertSame(
            "Wi-Fi and mobile data together: one clash is enough",
            TunnelAddresses.SPARE,
            TunnelAddresses.choose(listOf(network("100.64.12.3", 10), network("10.1.10.200", 24))),
        )
        assertSame(
            "networks that use both sets keep the common one: there is nothing better",
            TunnelAddresses.COMMON,
            TunnelAddresses.choose(listOf(network("10.1.10.5", 24), network("10.215.173.9", 24))),
        )
    }

    /** The engine's sets (core/net/src/engine.rs, `Addresses`) and these must be the same addresses. */
    @Test
    fun theSetsAreTheEnginesOwn() {
        val engine = File("../../core/net/src/engine.rs").readText()
        for (set in listOf(TunnelAddresses.COMMON, TunnelAddresses.SPARE)) {
            val name = set.name.uppercase()
            val block = Regex("pub const $name: Self = Self \\{(.*?)\\};", RegexOption.DOT_MATCHES_ALL).find(engine)
                ?.groupValues?.get(1) ?: error("engine.rs has no Addresses::$name")
            val fields = Regex("(\\w+): Ipv([46])Addr::new\\(([^)]*)\\)").findAll(block).associate { match ->
                val (field, family, args) = match.destructured
                val parts = args.split(",").map { it.trim() }
                val text = if (family == "4") {
                    parts.joinToString(".")
                } else {
                    parts.joinToString(":") { part -> Integer.parseInt(part.removePrefix("0x"), if (part.startsWith("0x")) 16 else 10).toString(16) }
                }
                field to ip(text)
            }
            val ours = mapOf(
                "tun4" to set.tun4, "fake4" to set.fake4, "dns4" to set.dns4,
                "tun6" to set.tun6, "fake6" to set.fake6, "dns6" to set.dns6,
            ).mapValues { ip(it.value) }
            assertEquals("Addresses::$name", ours, fields)
        }
    }
}
