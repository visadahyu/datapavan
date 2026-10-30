package org.visadahyu.datapavan.audit

import android.content.Context
import android.content.pm.PackageManager

/** A system service that some SDK capabilities need, such as Google Play services (ADR 0021). */
data class SystemService(val id: String, val name: String, val packages: List<String>)

/** What the phone has of a service, in the profile Datapavan runs in. */
enum class ServiceState {
    /** Installed, enabled and signed with a certificate the vendor's own library accepts. */
    GENUINE,

    /** Installed and enabled, but a replacement such as microG, or signed by a key not on the list. */
    SUBSTITUTE,

    /** Not installed, or turned off. */
    ABSENT,
}

/** A capability of an SDK that works only with all of [services], found by its class in an app. */
data class Capability(
    /** Its id in the tracker scanner, at or above [ServiceNeeds.FIRST_ID]. */
    val id: Int,
    /** Its key in `data/sdk-needs`, such as `google-ad-id`; the app names the capabilities it knows. */
    val key: String,
    val services: List<String>,
)

/**
 * SDK capabilities that need a system service, and the certificates of each service's genuine
 * packages (`data/sdk-needs`, ADR 0021). Their classes join the tracker scanner's signatures, like
 * the SDKs of [SdkList].
 */
class ServiceNeeds private constructor(
    val services: Map<String, SystemService>,
    val capabilities: List<Capability>,
    private val identifiers: Map<Int, String>,
    /** Certificate SHA-256 values of each service's genuine packages, by service. */
    val signers: Map<String, Set<String>>,
) {
    private val byId = capabilities.associateBy { it.id }

    fun byId(id: Int): Capability? = byId[id]

    /** The capabilities' classes in the scanner's format (that of `data/exodus/trackers.tsv`). */
    fun signatureTsv(): String = capabilities.mapNotNull { capability ->
        identifiers[capability.id]?.let { "${capability.id}\t${capability.key}\t\t\t$it\t" }
    }.joinToString("\n")

    /**
     * Whether [capability] cannot work right now: one of the services it needs is absent or turned
     * off. A substitute counts as present, because it may provide the service.
     */
    fun unavailable(capability: Capability, states: Map<String, ServiceState>): Boolean =
        capability.services.any { states[it] == ServiceState.ABSENT }

    /** The state of each service on this phone, in this profile, now. */
    fun read(context: Context): Map<String, ServiceState> = services.mapValues { (id, service) ->
        ServiceCheck.state(service.packages.map { packageFacts(context.packageManager, it) }, signers[id].orEmpty())
    }

    private fun packageFacts(pm: PackageManager, packageName: String): ServicePackage? = try {
        val info = pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS or PackageManager.GET_META_DATA)
        ServicePackage(
            enabled = info.applicationInfo?.enabled == true,
            signedBy = { sha256 -> pm.hasSigningCertificate(packageName, hex(sha256), PackageManager.CERT_INPUT_SHA256) },
            microgMarkers = info.requestedPermissions.orEmpty().any { it == FAKE_SIGNATURE_PERMISSION } ||
                info.applicationInfo?.metaData?.containsKey(FAKE_SIGNATURE_META_DATA) == true,
        )
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }

    companion object {
        const val SERVICES_PATH = "sdk-needs/services.tsv"
        const val CAPABILITIES_PATH = "sdk-needs/capabilities.tsv"
        const val SIGNERS_PATH = "sdk-needs/signers.tsv"
        const val FIRST_ID = 2_000_000

        /** Grades 1 to 3 ship; 4 means the vendor's artefact is not read yet. */
        private const val MAX_SHIPPED_GRADE = 3
        private const val FAKE_SIGNATURE_PERMISSION = "android.permission.FAKE_PACKAGE_SIGNATURE"
        private const val FAKE_SIGNATURE_META_DATA = "fake-signature"
        private val SHA256 = Regex("[0-9a-f]{64}")

        /** Reads the three files as `data/sdk-needs` holds them. Malformed lines are skipped. */
        fun parse(services: String, capabilities: String, signers: String): ServiceNeeds {
            val known = rows(services).filter { it.size >= 3 }
                .associate { it[0] to SystemService(it[0], it[1], it[2].split(',').filter(String::isNotBlank)) }
            val usable = rows(capabilities).filter { columns ->
                columns.size >= 5 && columns[2] == "class" && (columns[4].toIntOrNull() ?: Int.MAX_VALUE) <= MAX_SHIPPED_GRADE &&
                    columns[1].split(',').all { it in known }
            }
            val list = usable.mapIndexed { index, columns -> Capability(FIRST_ID + index, columns[0], columns[1].split(',')) }
            return ServiceNeeds(
                known,
                list,
                list.zip(usable).associate { (capability, columns) -> capability.id to columns[3] },
                rows(signers).filter { it.size >= 2 && it[0] in known && SHA256.matches(it[1]) }
                    .groupBy({ it[0] }, { it[1] }).mapValues { it.value.toSet() },
            )
        }

        private fun hex(text: String) = ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

        private fun rows(tsv: String) = tsv.lineSequence()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .map { it.split('\t') }
            .toList()
    }
}

/** What the service check needs to know about one installed package. */
data class ServicePackage(
    val enabled: Boolean,
    /** Whether the package is signed with the certificate whose SHA-256 is given, rotation included. */
    val signedBy: (String) -> Boolean,
    /** microG's own marks: its fake-signature permission or meta-data (ADR 0021). */
    val microgMarkers: Boolean,
)

/** Judges a service from the packages that may provide it; null for a package not installed. */
object ServiceCheck {
    fun state(packages: List<ServicePackage?>, signers: Set<String>): ServiceState {
        val present = packages.filterNotNull().filter { it.enabled }
        return when {
            present.isEmpty() -> ServiceState.ABSENT
            // microG can carry Google's certificate on some systems, so its marks decide first.
            present.any { !it.microgMarkers && signers.any(it.signedBy) } -> ServiceState.GENUINE
            else -> ServiceState.SUBSTITUTE
        }
    }
}
