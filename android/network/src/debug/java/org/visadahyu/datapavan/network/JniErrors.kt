package org.visadahyu.datapavan.network

import java.lang.reflect.InvocationTargetException

/**
 * Debug builds only (the cold paths' second pass, ADR 0053; its plan's audit, m5): the JNI bridge's error path, which
 * the emulator checks reach no other way (scripts/verify-network.sh). For each return type whose entry point an input
 * can make fail, the entry point is called by reflection with a null where Kotlin's type allows none, which the jni
 * crate refuses before any other work, and then the bridge is called again with an input it takes:
 * - `Unit`: [Engine.nativeTunnelOrder] with no array, then [Engine.nativeFlushLog], which hands the log what waits;
 * - `Boolean`: [Engine.nativeStates] with no message, then with an empty one, which is not a message and changes nothing;
 * - `String`: [Engine.nativeTunnelParse] with no text, then with an empty one, which it refuses;
 * - `IntArray`: [Engine.nativeReadDataPayload] with no payload, then with an empty one, which it reads as no payload.
 *
 * The failing call must throw a `RuntimeException` whose message starts "Rust error:", the bridge's error policy
 * (`ThrowRuntimeExAndDefault`), and the next call must return, with a value where its type has one. The default value
 * the policy returns with the exception cannot be read here: Java drops a native method's return value when an
 * exception is pending. Not checked: `Int` (`nativeRouteMtu` cannot fail), `ByteArray` and `LongArray`
 * (`nativeActivity` and `nativeCounters` take no input), and the panic path, which only debug builds catch (a release
 * build aborts) and no input reaches. One line per type, `jni-error TYPE ok` or `jni-error TYPE failed: WHY`; release
 * builds carry none: their JniErrors, in src/release, gives no line.
 */
object JniErrors {
    fun check(): List<String> = listOf(
        line("unit", fails("nativeTunnelOrder", IntArray::class.java)) { Engine.nativeFlushLog() },
        line("boolean", fails("nativeStates", ByteArray::class.java)) {
            Engine.nativeStates(ByteArray(0)).let { if (it) "an empty message read as one" else null }
        },
        line("string", fails("nativeTunnelParse", ByteArray::class.java)) {
            Engine.nativeTunnelParse(ByteArray(0)).let { if (it.startsWith("refused")) null else "an empty text gave \"$it\"" }
        },
        line("int-array", fails("nativeReadDataPayload", ByteArray::class.java)) {
            // Nullable here: a bridge that returned no array gives null, whatever Kotlin's type says.
            val read: IntArray? = Engine.nativeReadDataPayload(ByteArray(0))
            if (read == null) "an empty payload gave no array" else null
        },
    )

    /** What calling the entry point [name], whose one parameter is of [type], with null threw, or null if nothing. */
    private fun fails(name: String, type: Class<*>): Throwable? = try {
        Engine::class.java.getMethod(name, type).invoke(Engine, null)
        null
    } catch (e: InvocationTargetException) {
        e.targetException
    }

    /** The line of the return type [type]: the failing call threw [thrown], and [again], the next call, says what went wrong or null. */
    private fun line(type: String, thrown: Throwable?, again: () -> Any?): String {
        val why = when {
            thrown == null -> "the call with a null threw nothing"
            thrown.javaClass != RuntimeException::class.java -> "the call with a null threw ${thrown.javaClass.name}"
            thrown.message?.startsWith("Rust error:") != true -> "the call with a null threw \"${thrown.message}\""
            else -> try {
                (again() as? String)?.let { "the next call: $it" }
            } catch (e: Throwable) {
                "the next call threw ${e.javaClass.name}: ${e.message}"
            }
        }
        return if (why == null) "jni-error $type ok" else "jni-error $type failed: $why"
    }
}
